// Package dns 提供多 DNS 服务商（Cloudflare / 阿里云云解析 / 阿里云 ESA）的统一写入与探测能力。
//
// 设计目标：
//   - 每个服务商独立配置、独立启停，缺少配置时自动跳过而不是报错；
//   - 多个服务商可以同时启用，一次注册向全部启用的服务商写入记录；
//   - 写入是幂等的：记录已存在且内容一致时不重复改动，内容不一致时更新；
//   - 单个服务商失败不影响其它服务商，调用方可以按服务商粒度上报结果。
package dns

import (
	"context"
	"fmt"
	"net/http"

	"reg-to/config"
	"strings"
	"sync"
	"time"
)

// httpTimeout 是单个 DNS 服务商单次 API 调用的超时时间。
const httpTimeout = 20 * time.Second

// httpClient 是所有服务商共用的、带超时的 HTTP 客户端。
var httpClient = &http.Client{Timeout: httpTimeout}

// Action 描述一条记录本次实际发生的改动。
type Action string

const (
	// ActionCreated 表示本次新建了记录。
	ActionCreated Action = "created"
	// ActionUpdated 表示记录已存在但内容不一致，本次更新了记录。
	ActionUpdated Action = "updated"
	// ActionUnchanged 表示记录已存在且内容一致，无需改动。
	ActionUnchanged Action = "unchanged"
)

// RecordResult 是单条 DNS 记录的处理结果。
type RecordResult struct {
	FQDN     string `json:"fqdn"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Line     string `json:"line,omitempty"`
	Action   Action `json:"action"`
	RecordID string `json:"record_id,omitempty"`
}

// Outcome 是单个服务商在本次操作中的结果，可直接序列化返回给调用方。
type Outcome struct {
	Provider string         `json:"provider"`
	Label    string         `json:"label"`
	Enabled  bool           `json:"enabled"`
	OK       bool           `json:"ok"`
	Skipped  bool           `json:"skipped,omitempty"`
	Exists   bool           `json:"exists,omitempty"`
	Public   bool           `json:"public"`
	FQDN     string         `json:"fqdn,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	Error    string         `json:"error,omitempty"`
	Records  []RecordResult `json:"records,omitempty"`
}

// Provider 是一个可写入的 DNS 服务商。
type Provider interface {
	// ID 返回服务商标识，与 DNS_PROVIDERS 中的取值一致。
	ID() string
	// Label 返回用于展示的中文名称。
	Label() string
	// FQDN 返回给定子域名在该服务商下的完整记录名。
	FQDN(subdomain string) string
	// Public 报告该服务商写出的域名是否作为对用户可见的访问地址。
	//
	// 为 false 时依然会写入记录，但不会出现在返回给用户的 urls 里。
	// 典型场景：Cloudflare 侧域名只是智能解析的境外线路目标，不是租户的正式地址。
	Public() bool
	// Ensure 幂等地创建或更新该子域名的记录。
	Ensure(ctx context.Context, subdomain string) ([]RecordResult, error)
	// Exists 报告该子域名是否已经存在记录（任意类型）。
	Exists(ctx context.Context, subdomain string) (bool, error)
}

// Disabled 描述一个因配置缺失而未启用的服务商。
type Disabled struct {
	ID     string
	Label  string
	Reason string
}

// BulkRepointable 是支持按目标值批量改指的 DNS 服务商。
//
// 用于切换回源目标之后迁移存量记录，例如把回源从源站改为 ESA 接入域名。
type BulkRepointable interface {
	Provider
	// Repoint 把该服务商下所有指向 from 的记录改指到自身配置的目标。
	// dryRun 为 true 时只报告将要改动的内容，不真正写入。
	Repoint(ctx context.Context, from string, dryRun bool) ([]RecordResult, error)
}

// Manager 持有一组已启用的服务商，并向它们分发操作。
// 零值不可用，必须通过 Build 或 NewManager 构造。
type Manager struct {
	providers []Provider
	disabled  []Disabled
}

// NewManager 用给定的服务商装配 Manager，顺序即优先级顺序。
// 常规场景请使用 Build，本函数用于自定义装配与测试。
func NewManager(providers ...Provider) *Manager {
	return &Manager{providers: providers}
}

// Providers 返回已启用的服务商，顺序即配置中的优先级顺序。
func (m *Manager) Providers() []Provider { return m.providers }

// Disabled 返回因配置缺失被跳过的服务商。
func (m *Manager) Disabled() []Disabled { return m.disabled }

// Empty 报告是否没有任何已启用的服务商。
func (m *Manager) Empty() bool { return len(m.providers) == 0 }

// Has 报告给定服务商是否已启用。
func (m *Manager) Has(id string) bool {
	for _, provider := range m.providers {
		if provider.ID() == id {
			return true
		}
	}
	return false
}

// DisabledOutcomes 把被跳过的服务商转换为可上报的结果。
func (m *Manager) DisabledOutcomes() []Outcome {
	out := make([]Outcome, 0, len(m.disabled))
	for _, d := range m.disabled {
		out = append(out, Outcome{
			Provider: d.ID,
			Label:    d.Label,
			Enabled:  false,
			Skipped:  true,
			Reason:   d.Reason,
		})
	}
	return out
}

// run 并发执行全部已启用服务商，并按配置顺序返回结果。
func (m *Manager) run(
	ctx context.Context,
	subdomain string,
	fn func(context.Context, Provider, string) ([]RecordResult, bool, error),
) []Outcome {
	outcomes := make([]Outcome, len(m.providers))
	var wg sync.WaitGroup

	for i, provider := range m.providers {
		wg.Add(1)
		go func(idx int, p Provider) {
			defer wg.Done()
			records, exists, err := fn(ctx, p, subdomain)
			outcome := Outcome{
				Provider: p.ID(),
				Label:    p.Label(),
				Enabled:  true,
				Public:   p.Public(),
				FQDN:     p.FQDN(subdomain),
				Exists:   exists,
				// 即使后续步骤失败也保留已完成的记录，便于按服务商粒度上报部分成功。
				Records: records,
			}
			if err != nil {
				outcome.Error = err.Error()
			} else {
				outcome.OK = true
			}
			outcomes[idx] = outcome
		}(i, provider)
	}

	wg.Wait()
	return outcomes
}

// EnsureAll 向全部已启用服务商幂等写入记录。
func (m *Manager) EnsureAll(ctx context.Context, subdomain string) []Outcome {
	return m.run(ctx, subdomain, func(ctx context.Context, p Provider, sub string) ([]RecordResult, bool, error) {
		records, err := p.Ensure(ctx, sub)
		return records, false, err
	})
}

// RepointAll 让全部已启用服务商把指向 from 的记录改指到各自配置的目标。
//
// 这是维护操作，顺序执行即可，避免批量写入时把上游 API 打满。
func (m *Manager) RepointAll(ctx context.Context, from string, dryRun bool) []Outcome {
	outcomes := make([]Outcome, 0, len(m.providers))

	for _, provider := range m.providers {
		outcome := Outcome{
			Provider: provider.ID(),
			Label:    provider.Label(),
			Enabled:  true,
			Public:   provider.Public(),
		}

		repointable, ok := provider.(BulkRepointable)
		if !ok {
			outcome.Error = "该服务商不支持批量改指"
			outcomes = append(outcomes, outcome)
			continue
		}

		records, err := repointable.Repoint(ctx, from, dryRun)
		outcome.Records = records
		if err != nil {
			outcome.Error = err.Error()
		} else {
			outcome.OK = true
		}
		outcomes = append(outcomes, outcome)
	}

	return outcomes
}

// CheckAll 探测全部已启用服务商上该子域名是否已被占用。
func (m *Manager) CheckAll(ctx context.Context, subdomain string) []Outcome {
	return m.run(ctx, subdomain, func(ctx context.Context, p Provider, sub string) ([]RecordResult, bool, error) {
		exists, err := p.Exists(ctx, sub)
		return nil, exists, err
	})
}

// AnyOK 报告是否至少有一个服务商操作成功。
func AnyOK(outcomes []Outcome) bool {
	for _, o := range outcomes {
		if o.OK {
			return true
		}
	}
	return false
}

// AnyExists 报告是否有任一服务商已存在该子域名。
func AnyExists(outcomes []Outcome) bool {
	for _, o := range outcomes {
		if o.OK && o.Exists {
			return true
		}
	}
	return false
}

// FQDNs 按优先级顺序收集对外暴露、且写入成功的完整域名，并去重。
//
// 标记为不对外暴露的服务商（例如只作为智能解析回源目标的 Cloudflare）不会出现在结果里。
// 若没有任何服务商对外暴露，返回空列表 —— 调用方应据此提示「没有可用的公开访问地址」，
// 而不是把仅用于回源的地址暴露给用户，那会违反 Provider.Public 的约定。
func FQDNs(outcomes []Outcome) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		if !o.OK || !o.Public || o.FQDN == "" || seen[o.FQDN] {
			continue
		}
		seen[o.FQDN] = true
		out = append(out, o.FQDN)
	}
	return out
}

// checkRepointSubdomain 在批量改指前确认子域名可解析。
//
// 目标里带 {sub} 时，若记录名不在本服务管理的域名空间内，展开会得到缺少
// 子域名的错误目标（例如 ".cf.getastra.cn"），因此这里直接拒绝而不是写坏记录。
func checkRepointSubdomain(subdomain, target, recordName string) error {
	if subdomain != "" || !strings.Contains(target, config.SubPlaceholder) {
		return nil
	}
	return fmt.Errorf("记录 %s 不在本服务管理的域名空间内，无法展开 %s 目标",
		recordName, config.SubPlaceholder)
}

// duplicateErrorMarkers 是各服务商表示「记录已存在」的错误特征。
var duplicateErrorMarkers = []string{
	"domainrecordduplicate", // 阿里云云解析
	"recordalreadyexists",   // 阿里云 ESA
	"already exists",        // Cloudflare
	"alreadyexist",
	"duplicate",
}

// isDuplicateRecordError 判断错误是否表示记录已存在。
//
// 并发注册请求可能同时通过「先查询」这一关，随后其中一个创建成功、
// 另一个拿到冲突错误。此时应重新查询并视为成功，而不是把成功当失败返回。
func isDuplicateRecordError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range duplicateErrorMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// Failures 返回配置了但操作失败的服务商名称与原因，用于提示用户。
func Failures(outcomes []Outcome) []string {
	out := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		if o.OK || o.Skipped {
			continue
		}
		out = append(out, o.Label+": "+o.Error)
	}
	return out
}

// joinName 把子域名、可选记录后缀与根域名拼成完整记录名。
func joinName(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ".")
}

// relativeName 返回相对于根域名的记录名（RR），例如 school 或 school.cf。
func relativeName(subdomain, suffix string) string {
	if suffix == "" {
		return subdomain
	}
	return subdomain + "." + suffix
}

func strPtr(v string) *string { return &v }

func intPtr(v int) *int { return &v }

// optionalStr 在值为空时返回 nil，让 SDK 使用自身的默认值。
func optionalStr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}
