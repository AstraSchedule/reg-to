package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"reg-to/config"
)

// cfMaxResponseBytes 限制单次读取的 Cloudflare 响应体积。
const cfMaxResponseBytes = 1 << 20

type cloudflareProvider struct {
	cfg config.CloudflareConfig
}

func newCloudflareProvider(cfg config.CloudflareConfig) Provider {
	return &cloudflareProvider{cfg: cfg}
}

func (p *cloudflareProvider) ID() string { return config.ProviderCloudflare }

func (p *cloudflareProvider) Label() string { return "Cloudflare" }

func (p *cloudflareProvider) FQDN(subdomain string) string {
	return joinName(subdomain, p.cfg.RecordSuffix, p.cfg.ZoneName)
}

func (p *cloudflareProvider) Public() bool { return p.cfg.Public }

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfResultInfo 是 Cloudflare 的分页信息。
type cfResultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
	TotalCount int `json:"total_count"`
}

type cfEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfError       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *cfResultInfo   `json:"result_info"`
}

// do 发送一次 Cloudflare API 请求，只返回 result 部分。
func (p *cloudflareProvider) do(ctx context.Context, method, path string, payload any) (json.RawMessage, error) {
	envelope, err := p.doEnvelope(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}
	return envelope.Result, nil
}

// doEnvelope 发送一次 Cloudflare API 请求并解包统一响应结构。
func (p *cloudflareProvider) doEnvelope(ctx context.Context, method, path string, payload any) (*cfEnvelope, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("序列化 Cloudflare 请求失败: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	endpoint := strings.TrimRight(p.cfg.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("构造 Cloudflare 请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare 请求失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, cfMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 Cloudflare 响应失败: %w", err)
	}

	var envelope cfEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("解析 Cloudflare 响应失败 (HTTP %d): %w", resp.StatusCode, err)
	}
	if !envelope.Success {
		detail := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(envelope.Errors) > 0 {
			detail = fmt.Sprintf("code %d: %s", envelope.Errors[0].Code, envelope.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare API 错误: %s", detail)
	}
	return &envelope, nil
}

// list 按记录名查询该名称下的全部记录。
func (p *cloudflareProvider) list(ctx context.Context, fqdn string, recordType string) ([]cfRecord, error) {
	query := url.Values{}
	query.Set("name", fqdn)
	if recordType != "" {
		query.Set("type", recordType)
	}
	path := fmt.Sprintf("/zones/%s/dns_records?%s", url.PathEscape(p.cfg.ZoneID), query.Encode())

	raw, err := p.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var records []cfRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("解析 Cloudflare 记录列表失败: %w", err)
	}
	return records, nil
}

func (p *cloudflareProvider) findRecord(ctx context.Context, fqdn string) (*cfRecord, error) {
	records, err := p.list(ctx, fqdn, "CNAME")
	if err != nil {
		return nil, err
	}
	for i := range records {
		if strings.EqualFold(records[i].Name, fqdn) {
			return &records[i], nil
		}
	}
	return nil, nil
}

// listAll 分页拉取 zone 内指定类型的全部记录。
func (p *cloudflareProvider) listAll(ctx context.Context, recordType string) ([]cfRecord, error) {
	const perPage = 100

	all := make([]cfRecord, 0, perPage)
	for page := 1; ; page++ {
		query := url.Values{}
		query.Set("page", strconv.Itoa(page))
		query.Set("per_page", strconv.Itoa(perPage))
		if recordType != "" {
			query.Set("type", recordType)
		}
		path := fmt.Sprintf("/zones/%s/dns_records?%s", url.PathEscape(p.cfg.ZoneID), query.Encode())

		envelope, err := p.doEnvelope(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}

		var records []cfRecord
		if err := json.Unmarshal(envelope.Result, &records); err != nil {
			return nil, fmt.Errorf("解析 Cloudflare 记录列表失败: %w", err)
		}
		all = append(all, records...)

		if len(records) == 0 {
			return all, nil
		}
		// 有分页信息时按总页数判断；缺失时退回到「本页不足一页即结束」，
		// 不能因为拿不到 result_info 就在第一页之后提前收工。
		if envelope.ResultInfo != nil {
			if envelope.ResultInfo.TotalPages <= page {
				return all, nil
			}
			continue
		}
		if len(records) < perPage {
			return all, nil
		}
	}
}

// Repoint 把 zone 内所有指向 from 的 CNAME 记录改指到当前配置的目标。
//
// 只动内容恰好等于 from 的记录，不会触碰其它记录（例如各服务自身的域名）。
func (p *cloudflareProvider) Repoint(ctx context.Context, from string, dryRun bool) ([]RecordResult, error) {
	records, err := p.listAll(ctx, "CNAME")
	if err != nil {
		return nil, err
	}

	results := make([]RecordResult, 0, len(records))
	for _, record := range records {
		if record.Content != from {
			continue
		}

		subdomain := p.subdomainOf(record.Name)
		if err := checkRepointSubdomain(subdomain, p.cfg.Target, record.Name); err != nil {
			return results, err
		}
		target := config.ExpandTarget(p.cfg.Target, subdomain)
		result := RecordResult{
			FQDN:     record.Name,
			Type:     record.Type,
			Value:    target,
			RecordID: record.ID,
		}

		if dryRun {
			result.Action = ActionUpdated
			results = append(results, result)
			continue
		}

		payload := map[string]any{
			"type":    record.Type,
			"name":    record.Name,
			"content": target,
			"proxied": p.cfg.Proxied,
			"ttl":     p.cfg.EffectiveTTL(),
			"comment": "SaaS",
		}
		path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(p.cfg.ZoneID), url.PathEscape(record.ID))
		if _, err := p.do(ctx, http.MethodPut, path, payload); err != nil {
			return results, fmt.Errorf("改指 %s 失败: %w", record.Name, err)
		}

		result.Action = ActionUpdated
		results = append(results, result)
	}

	return results, nil
}

// subdomainOf 从完整记录名反推子域名，用于展开 {sub} 占位符。
// 名字不在本 zone 的域名空间内时返回空串。
func (p *cloudflareProvider) subdomainOf(fqdn string) string {
	suffix := "." + joinName(p.cfg.RecordSuffix, p.cfg.ZoneName)
	if !strings.HasSuffix(strings.ToLower(fqdn), strings.ToLower(suffix)) {
		return ""
	}
	return fqdn[:len(fqdn)-len(suffix)]
}

func (p *cloudflareProvider) Exists(ctx context.Context, subdomain string) (bool, error) {
	fqdn := p.FQDN(subdomain)
	records, err := p.list(ctx, fqdn, "")
	if err != nil {
		return false, err
	}
	for i := range records {
		if strings.EqualFold(records[i].Name, fqdn) {
			return true, nil
		}
	}
	return false, nil
}

// Ensure 幂等地保证子域名记录存在且指向配置的目标地址。
func (p *cloudflareProvider) Ensure(ctx context.Context, subdomain string) ([]RecordResult, error) {
	fqdn := p.FQDN(subdomain)
	target := config.ExpandTarget(p.cfg.Target, subdomain)
	ttl := p.cfg.EffectiveTTL()

	payload := map[string]any{
		"type":    "CNAME",
		"name":    fqdn,
		"content": target,
		"proxied": p.cfg.Proxied,
		"ttl":     ttl,
		"comment": "SaaS",
	}

	existing, err := p.findRecord(ctx, fqdn)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		created, duplicated, createErr := p.createRecord(ctx, fqdn, payload)
		switch {
		case createErr != nil:
			return nil, createErr
		case duplicated:
			// 并发下已被其它实例创建，转入下面的对账流程而不是直接报成功：
			// 对方写进去的可能是旧目标或旧代理状态。
			existing = created
		default:
			return []RecordResult{{
				FQDN: fqdn, Type: "CNAME", Value: target,
				Action: ActionCreated, RecordID: created.ID,
			}}, nil
		}
	}

	return p.reconcile(ctx, fqdn, target, ttl, existing, payload)
}

// createRecord 尝试新建记录。
//
// duplicated 为 true 时表示并发下记录已存在，返回的是查询到的现有记录，
// 调用方应转入对账流程。
func (p *cloudflareProvider) createRecord(ctx context.Context, fqdn string, payload map[string]any) (record *cfRecord, duplicated bool, err error) {
	path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(p.cfg.ZoneID))

	raw, err := p.do(ctx, http.MethodPost, path, payload)
	if err == nil {
		created := &cfRecord{}
		// 创建已成功；回包解析失败只意味着拿不到记录 ID，不影响幂等结果。
		if json.Unmarshal(raw, created) == nil {
			return created, false, nil
		}
		return &cfRecord{}, false, nil
	}
	if !isDuplicateRecordError(err) {
		return nil, false, err
	}

	found, lookupErr := p.findRecord(ctx, fqdn)
	if lookupErr != nil || found == nil {
		return nil, false, err
	}
	return found, true, nil
}

// reconcile 把已存在的记录对齐到期望状态。
func (p *cloudflareProvider) reconcile(
	ctx context.Context,
	fqdn, target string,
	ttl int,
	existing *cfRecord,
	payload map[string]any,
) ([]RecordResult, error) {
	result := RecordResult{FQDN: fqdn, Type: "CNAME", Value: target, RecordID: existing.ID}

	if existing.Content == target && existing.Proxied == p.cfg.Proxied && existing.TTL == ttl {
		result.Value = existing.Content
		result.Action = ActionUnchanged
		return []RecordResult{result}, nil
	}

	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(p.cfg.ZoneID), url.PathEscape(existing.ID))
	if _, err := p.do(ctx, http.MethodPut, path, payload); err != nil {
		return nil, err
	}
	result.Action = ActionUpdated
	return []RecordResult{result}, nil
}
