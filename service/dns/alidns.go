package dns

import (
	"context"
	"fmt"
	"strings"

	"reg-to/config"

	alidns "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapiutil "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
)

type aliDNSProvider struct {
	cfg    config.AliDNSConfig
	client *alidns.Client
}

func newAliDNSProvider(cfg config.AliDNSConfig) (Provider, error) {
	client, err := alidns.NewClient(&openapiutil.Config{
		AccessKeyId:     strPtr(cfg.AccessKeyID),
		AccessKeySecret: strPtr(cfg.AccessKeySecret),
		Endpoint:        strPtr(cfg.Endpoint),
		Protocol:        optionalStr(cfg.Protocol),
		ReadTimeout:     intPtr(int(httpTimeout.Milliseconds())),
		ConnectTimeout:  intPtr(int(httpTimeout.Milliseconds())),
	})
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云云解析客户端失败: %w", err)
	}
	return &aliDNSProvider{cfg: cfg, client: client}, nil
}

func (p *aliDNSProvider) ID() string { return config.ProviderAliDNS }

func (p *aliDNSProvider) Label() string { return "阿里云云解析" }

func (p *aliDNSProvider) FQDN(subdomain string) string {
	return joinName(subdomain, p.cfg.RecordSuffix, p.cfg.DomainName)
}

func (p *aliDNSProvider) Public() bool { return p.cfg.Public }

// rr 返回相对于根域名的记录名。
func (p *aliDNSProvider) rr(subdomain string) string {
	return relativeName(subdomain, p.cfg.RecordSuffix)
}

// list 按记录名与线路精确查询解析记录。
//
// line 会作为查询条件发给服务端；这一点很关键：只有当服务端确实按线路过滤过，
// 下面才可以把「未回传 Line 字段」的记录视为该线路的命中。否则默认线路与境外线路
// 会匹配到同一条记录，导致后一条线路把前一条覆盖掉。
func (p *aliDNSProvider) list(ctx context.Context, rr, line string) ([]*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	req := (&alidns.DescribeDomainRecordsRequest{}).
		SetDomainName(p.cfg.DomainName).
		SetRRKeyWord(rr).
		SetSearchMode("EXACT").
		SetLine(line).
		SetPageNumber(1).
		SetPageSize(100)

	resp, err := p.client.DescribeDomainRecords(req)
	if err != nil {
		return nil, fmt.Errorf("查询云解析记录失败: %w", err)
	}
	if resp == nil || resp.Body == nil || resp.Body.DomainRecords == nil {
		return nil, nil
	}
	return resp.Body.DomainRecords.Record, nil
}

// findAliRecord 在已查询到的记录中定位指定线路的 CNAME 记录。
//
// 查询已带线路条件，因此记录未回传 Line 字段时可以视为命中；
// 一旦回传了 Line，就必须与目标线路一致。
func findAliRecord(records []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, rr, line string) *alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord {
	for _, record := range records {
		if record == nil {
			continue
		}
		if !strings.EqualFold(deref(record.RR), rr) || !strings.EqualFold(deref(record.Type), "CNAME") {
			continue
		}
		if recordLine := deref(record.Line); recordLine != "" && !strings.EqualFold(recordLine, line) {
			continue
		}
		return record
	}
	return nil
}

func (p *aliDNSProvider) Exists(ctx context.Context, subdomain string) (bool, error) {
	rr := p.rr(subdomain)
	// 占用判断与线路无关，必须不带线路条件查询：
	// 只查默认线路会漏掉「记录只存在于境外线路」的情况，把已占用的子域名误判为空闲。
	records, err := p.list(ctx, rr, "")
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record != nil && strings.EqualFold(deref(record.RR), rr) {
			return true, nil
		}
	}
	return false, nil
}

// Ensure 为每条已配置的解析线路幂等写入 CNAME 记录。
func (p *aliDNSProvider) Ensure(ctx context.Context, subdomain string) ([]RecordResult, error) {
	targets := p.cfg.Lines(subdomain)
	if len(targets) == 0 {
		return nil, fmt.Errorf("云解析未配置任何解析线路目标")
	}

	rr := p.rr(subdomain)
	fqdn := p.FQDN(subdomain)

	// 同一条记录绝不能同时服务于两条线路，否则后一条会覆盖前一条。
	usedRecordIDs := make(map[string]bool, len(targets))

	results := make([]RecordResult, 0, len(targets))
	for _, target := range targets {
		existing, err := p.lookupLine(ctx, rr, target.Line)
		if err != nil {
			return results, err
		}

		if existing != nil {
			recordID := deref(existing.RecordId)
			if recordID != "" && usedRecordIDs[recordID] {
				return results, fmt.Errorf(
					"线路 %s 与另一条线路匹配到同一条记录(%s)，已中止以免互相覆盖", target.Line, recordID)
			}
			usedRecordIDs[recordID] = true
		}

		result, err := p.ensureLine(ctx, rr, fqdn, target, existing)
		results = append(results, result)
		if err != nil {
			// 保留已完成线路的结果，便于调用方按线路粒度上报。
			return results, err
		}
	}
	return results, nil
}

// lookupLine 查询指定线路下该记录名的 CNAME 记录。
func (p *aliDNSProvider) lookupLine(ctx context.Context, rr, line string) (*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	records, err := p.list(ctx, rr, line)
	if err != nil {
		return nil, err
	}
	return findAliRecord(records, rr, line), nil
}

func (p *aliDNSProvider) ensureLine(
	ctx context.Context,
	rr, fqdn string,
	target config.LineTarget,
	existing *alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord,
) (RecordResult, error) {
	result := RecordResult{FQDN: fqdn, Type: "CNAME", Value: target.Target, Line: target.Line}

	if existing == nil {
		req := (&alidns.AddDomainRecordRequest{}).
			SetDomainName(p.cfg.DomainName).
			SetRR(rr).
			SetType("CNAME").
			SetValue(target.Target).
			SetLine(target.Line).
			SetTTL(int64(p.cfg.TTL))

		resp, err := p.client.AddDomainRecord(req)
		if err == nil {
			result.Action = ActionCreated
			if resp != nil && resp.Body != nil {
				result.RecordID = deref(resp.Body.RecordId)
			}
			return result, nil
		}
		if !isDuplicateRecordError(err) {
			return result, fmt.Errorf("创建云解析记录(线路 %s)失败: %w", target.Line, err)
		}

		// 并发注册时记录可能已被其它实例抢先创建。不能直接报成功：
		// 对方写进去的可能是旧目标或旧 TTL。重新查询后走下面的比较与更新流程。
		found, lookupErr := p.lookupLine(ctx, rr, target.Line)
		if lookupErr != nil || found == nil {
			return result, fmt.Errorf("创建云解析记录(线路 %s)失败: %w", target.Line, err)
		}
		existing = found
	}

	recordID := deref(existing.RecordId)
	result.RecordID = recordID

	if deref(existing.Value) == target.Target && derefInt64(existing.TTL) == int64(p.cfg.TTL) {
		result.Action = ActionUnchanged
		return result, nil
	}

	req := (&alidns.UpdateDomainRecordRequest{}).
		SetRecordId(recordID).
		SetRR(rr).
		SetType("CNAME").
		SetValue(target.Target).
		SetLine(target.Line).
		SetTTL(int64(p.cfg.TTL))

	if _, err := p.client.UpdateDomainRecord(req); err != nil {
		return result, fmt.Errorf("更新云解析记录(线路 %s)失败: %w", target.Line, err)
	}
	result.Action = ActionUpdated
	return result, nil
}
