package dns

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"reg-to/config"

	openapiutil "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	esa "github.com/alibabacloud-go/esa-20240910/v3/client"
)

type esaProvider struct {
	cfg    config.ESAConfig
	client *esa.Client
}

func newESAProvider(cfg config.ESAConfig) (Provider, error) {
	client, err := esa.NewClient(&openapiutil.Config{
		AccessKeyId:     strPtr(cfg.AccessKeyID),
		AccessKeySecret: strPtr(cfg.AccessKeySecret),
		Endpoint:        strPtr(cfg.Endpoint),
		Protocol:        optionalStr(cfg.Protocol),
		ReadTimeout:     intPtr(int(httpTimeout.Milliseconds())),
		ConnectTimeout:  intPtr(int(httpTimeout.Milliseconds())),
	})
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云 ESA 客户端失败: %w", err)
	}
	return &esaProvider{cfg: cfg, client: client}, nil
}

func (p *esaProvider) ID() string { return config.ProviderESA }

func (p *esaProvider) Label() string { return "阿里云 ESA" }

func (p *esaProvider) FQDN(subdomain string) string {
	return joinName(subdomain, p.cfg.RecordSuffix, p.cfg.SiteName)
}

func (p *esaProvider) Public() bool { return p.cfg.Public }

// list 精确查询站点内指定记录名的全部记录。
func (p *esaProvider) list(ctx context.Context, fqdn string) ([]*esa.ListRecordsResponseBodyRecords, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	req := (&esa.ListRecordsRequest{}).
		SetSiteId(p.cfg.SiteID).
		SetRecordName(fqdn).
		SetRecordMatchType("exact").
		SetPageNumber(1).
		SetPageSize(100)

	resp, err := p.client.ListRecords(req)
	if err != nil {
		return nil, fmt.Errorf("查询 ESA 记录失败: %w", err)
	}
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return resp.Body.Records, nil
}

func findEsaRecord(records []*esa.ListRecordsResponseBodyRecords, fqdn string) *esa.ListRecordsResponseBodyRecords {
	for _, record := range records {
		if record == nil {
			continue
		}
		if !strings.EqualFold(deref(record.RecordName), fqdn) {
			continue
		}
		if !strings.EqualFold(deref(record.RecordType), "CNAME") {
			continue
		}
		return record
	}
	return nil
}

// lookupRecord 重新查询指定记录名的 CNAME 记录。
func (p *esaProvider) lookupRecord(ctx context.Context, fqdn string) (*esa.ListRecordsResponseBodyRecords, error) {
	records, err := p.list(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	return findEsaRecord(records, fqdn), nil
}

func (p *esaProvider) Exists(ctx context.Context, subdomain string) (bool, error) {
	fqdn := p.FQDN(subdomain)
	records, err := p.list(ctx, fqdn)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record != nil && strings.EqualFold(deref(record.RecordName), fqdn) {
			return true, nil
		}
	}
	return false, nil
}

// Ensure 幂等地保证站点内存在指向配置目标的 CNAME 记录。
func (p *esaProvider) Ensure(ctx context.Context, subdomain string) ([]RecordResult, error) {
	fqdn := p.FQDN(subdomain)
	target := config.ExpandTarget(p.cfg.Target, subdomain)

	result := RecordResult{FQDN: fqdn, Type: "CNAME", Value: target}

	existing, created, err := p.ensureExists(ctx, fqdn, target)
	if err != nil {
		return nil, err
	}

	result.RecordID = fmt.Sprintf("%d", derefInt64(existing.RecordId))
	if created {
		result.Action = ActionCreated
		return []RecordResult{result}, nil
	}
	if p.matchesDesired(existing, target) {
		result.Value = esaRecordValue(existing)
		result.Action = ActionUnchanged
		return []RecordResult{result}, nil
	}

	if _, err := p.client.UpdateRecord(p.updateRequest(derefInt64(existing.RecordId), target, tenantCommentFor(existing))); err != nil {
		return nil, fmt.Errorf("更新 ESA 记录失败: %w", err)
	}
	result.Action = ActionUpdated
	return []RecordResult{result}, nil
}

// ensureExists 返回站点内的目标记录；不存在时先创建。
//
// created 为 true 表示本次新建成功，调用方直接按「已创建」返回即可。
// 创建遇到重复冲突说明记录已被并发实例抢先写入，此时重新查询并返回它，
// 由调用方统一走比较与更新流程 —— 对方写进去的可能是旧目标或旧回源配置。
func (p *esaProvider) ensureExists(
	ctx context.Context,
	fqdn, target string,
) (record *esa.ListRecordsResponseBodyRecords, created bool, err error) {
	records, err := p.list(ctx, fqdn)
	if err != nil {
		return nil, false, err
	}
	if existing := findEsaRecord(records, fqdn); existing != nil {
		return existing, false, nil
	}

	resp, err := p.client.CreateRecord(p.createRequest(fqdn, target))
	if err == nil {
		createdRecord := &esa.ListRecordsResponseBodyRecords{}
		if resp != nil && resp.Body != nil {
			createdRecord.RecordId = resp.Body.RecordId
		}
		return createdRecord, true, nil
	}
	if !isDuplicateRecordError(err) {
		return nil, false, fmt.Errorf("创建 ESA 记录失败: %w", err)
	}

	found, lookupErr := p.lookupRecord(ctx, fqdn)
	if lookupErr != nil || found == nil {
		return nil, false, fmt.Errorf("创建 ESA 记录失败: %w", err)
	}
	return found, false, nil
}

// createRequest 构造新建记录的请求。
func (p *esaProvider) createRequest(fqdn, target string) *esa.CreateRecordRequest {
	return (&esa.CreateRecordRequest{}).
		SetSiteId(p.cfg.SiteID).
		SetRecordName(fqdn).
		SetType("CNAME").
		SetData((&esa.CreateRecordRequestData{}).SetValue(target)).
		SetTtl(int32(p.cfg.TTL)).
		SetProxied(p.cfg.Proxied).
		SetBizName(p.cfg.BizName).
		SetSourceType(p.cfg.SourceType).
		SetComment(TenantComment)
}

// updateRequest 构造更新记录的请求。
//
// comment 由调用方按已有备注计算（见 tenantCommentFor），不在这里写死标记 ——
// 直接写死会把控制台上人工补充的备注抹掉。
func (p *esaProvider) updateRequest(recordID int64, target, comment string) *esa.UpdateRecordRequest {
	return (&esa.UpdateRecordRequest{}).
		SetRecordId(recordID).
		SetType("CNAME").
		SetData((&esa.UpdateRecordRequestData{}).SetValue(target)).
		SetTtl(int32(p.cfg.TTL)).
		SetProxied(p.cfg.Proxied).
		SetBizName(p.cfg.BizName).
		SetSourceType(p.cfg.SourceType).
		SetComment(comment)
}

// esaRecordValue 取出记录的目标值；Data 缺失时返回空串。
func esaRecordValue(record *esa.ListRecordsResponseBodyRecords) string {
	if record == nil || record.Data == nil {
		return ""
	}
	return deref(record.Data.Value)
}

// matchesDesired 报告已有记录是否与期望状态一致。
//
// 期望状态包含目标值、代理开关、TTL、回源类型、业务场景与租户备注标记六项；
// 少比较任意一项都会让配置改动「看起来已生效」却实际没写入 ——
// 例如把回源从普通域名改成源地址池（OP）、把业务场景从 web 改成 api，
// 或者漏掉租户标记导致系统端认不出这条记录。
func (p *esaProvider) matchesDesired(existing *esa.ListRecordsResponseBodyRecords, target string) bool {
	return esaRecordValue(existing) == target &&
		derefBool(existing.Proxied) == p.cfg.Proxied &&
		derefInt64(existing.Ttl) == int64(p.cfg.TTL) &&
		strings.EqualFold(deref(existing.RecordSourceType), p.cfg.SourceType) &&
		strings.EqualFold(deref(existing.BizName), p.cfg.BizName) &&
		hasTenantComment(existing)
}

// hasTenantComment 报告已有记录是否带租户备注标记。
func hasTenantComment(record *esa.ListRecordsResponseBodyRecords) bool {
	return record != nil && hasTenantMarker(deref(record.Comment))
}

// hasTenantMarker 判断备注是否以租户标记开头，是便于单测的纯函数。
//
// 只认「标记出现在开头」：备注等于标记，或标记之后紧跟非字母数字字符（如「SaaS 租户」）。
// 不用子串匹配，是因为 "non-SaaS" 这类反向说明会被误判成租户标记；
// 系统端（sys-backend）用同一规则读取，两边必须保持一致。
func hasTenantMarker(comment string) bool {
	trimmed := strings.TrimSpace(comment)
	if len(trimmed) < len(TenantComment) {
		return false
	}
	if !strings.EqualFold(trimmed[:len(TenantComment)], TenantComment) {
		return false
	}
	if len(trimmed) == len(TenantComment) {
		return true
	}
	next, _ := utf8.DecodeRuneInString(trimmed[len(TenantComment):])
	return !unicode.IsLetter(next) && !unicode.IsDigit(next)
}

// tenantCommentFor 返回写回记录时应使用的备注。
//
// 备注可能被人为补充过（如「SaaS 租户 nj39」），已有标记时原样保留，
// 只在缺标记时补上，否则每次写入都会抹掉人工补充的信息。
func tenantCommentFor(record *esa.ListRecordsResponseBodyRecords) string {
	if hasTenantComment(record) {
		return deref(record.Comment)
	}
	return TenantComment
}

// listAll 分页拉取站点内的全部 CNAME 记录，供批量改指使用。
func (p *esaProvider) listAll(ctx context.Context) ([]*esa.ListRecordsResponseBodyRecords, error) {
	const pageSize = 100

	all := make([]*esa.ListRecordsResponseBodyRecords, 0, pageSize)
	for page := 1; ; page++ {
		records, total, err := p.fetchPage(ctx, page, pageSize)
		if err != nil {
			return nil, err
		}

		all = append(all, records...)
		if !hasMorePages(records, len(all), total, pageSize) {
			return all, nil
		}
	}
}

// fetchPage 拉取一页记录，并返回服务端给出的总数（可能为 nil）。
func (p *esaProvider) fetchPage(
	ctx context.Context,
	page, pageSize int,
) (records []*esa.ListRecordsResponseBodyRecords, total *int32, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	req := (&esa.ListRecordsRequest{}).
		SetSiteId(p.cfg.SiteID).
		SetType("CNAME").
		SetPageNumber(int32(page)).
		SetPageSize(int32(pageSize))

	resp, err := p.client.ListRecords(req)
	if err != nil {
		return nil, nil, fmt.Errorf("查询 ESA 记录失败: %w", err)
	}
	if resp == nil || resp.Body == nil {
		return nil, nil, nil
	}
	return resp.Body.Records, resp.Body.TotalCount, nil
}

// hasMorePages 判断是否还有下一页。
//
// 有总数时按总数判断；总数缺失时退回到「本页不足一页即结束」——
// 不能把缺失当成 0，否则第一页之后就会提前收工、漏掉后续记录。
func hasMorePages(records []*esa.ListRecordsResponseBodyRecords, collected int, total *int32, pageSize int) bool {
	if len(records) == 0 {
		return false
	}
	if total != nil {
		return collected < int(*total)
	}
	return len(records) >= pageSize
}

// Repoint 把站点内所有指向 from 的 CNAME 记录改指到当前配置的目标。
//
// 只动内容恰好等于 from 的记录，不会触碰其它记录。
func (p *esaProvider) Repoint(ctx context.Context, from string, dryRun bool) ([]RecordResult, error) {
	records, err := p.listAll(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]RecordResult, 0, len(records))
	for _, record := range records {
		if record == nil || record.Data == nil || deref(record.Data.Value) != from {
			continue
		}

		fqdn := deref(record.RecordName)
		subdomain := p.subdomainOf(fqdn)
		if err := checkRepointSubdomain(subdomain, p.cfg.Target, fqdn); err != nil {
			return results, err
		}
		target := config.ExpandTarget(p.cfg.Target, subdomain)
		recordID := derefInt64(record.RecordId)
		result := RecordResult{
			FQDN:     fqdn,
			Type:     "CNAME",
			Value:    target,
			RecordID: fmt.Sprintf("%d", recordID),
		}

		if dryRun {
			result.Action = ActionUpdated
			results = append(results, result)
			continue
		}

		// 与 Ensure 一致：一次把期望状态整体写回，顺带纠正 TTL 与回源配置。
		req := (&esa.UpdateRecordRequest{}).
			SetRecordId(recordID).
			SetType("CNAME").
			SetData((&esa.UpdateRecordRequestData{}).SetValue(target)).
			SetTtl(int32(p.cfg.TTL)).
			SetProxied(p.cfg.Proxied).
			SetBizName(p.cfg.BizName).
			SetSourceType(p.cfg.SourceType).
			SetComment(tenantCommentFor(record))

		if _, err := p.client.UpdateRecord(req); err != nil {
			return results, fmt.Errorf("改指 %s 失败: %w", fqdn, err)
		}
		result.Action = ActionUpdated
		results = append(results, result)
	}

	return results, nil
}

// subdomainOf 从完整记录名反推子域名，用于展开 {sub} 占位符。
func (p *esaProvider) subdomainOf(fqdn string) string {
	suffix := "." + joinName(p.cfg.RecordSuffix, p.cfg.SiteName)
	if !strings.HasSuffix(strings.ToLower(fqdn), strings.ToLower(suffix)) {
		return ""
	}
	return fqdn[:len(fqdn)-len(suffix)]
}
