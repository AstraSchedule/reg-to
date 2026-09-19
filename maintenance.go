package main

import (
	"context"
	"flag"
	"log"
	"time"

	"reg-to/service/dns"
)

// maintenanceTimeout 是批量改指的总超时。
const maintenanceTimeout = 10 * time.Minute

// maintenanceRequested 判断是否以维护模式启动。
//
// 只认第一个参数：运行时（如函数计算）可能追加参数，不能把它们误当成维护指令。
func maintenanceRequested(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return args[0] == "-sync-dns" || args[0] == "--sync-dns"
}

// printSyncUsage 打印批量改指的用法。
func printSyncUsage() {
	log.Println("用法: reg-to -sync-dns -from <旧目标值> [-apply]")
	log.Println()
	log.Println("把存量 DNS 记录从旧目标批量改指到当前配置的目标。")
	log.Println("典型场景：回源从源站改为 ESA 接入域名后，迁移已有租户的记录。")
	log.Println()
	log.Println("  -from    要替换掉的旧目标值，例如 class.getastra.cn（必填）")
	log.Println("  -apply   真正写入改动；不加时只预览")
	log.Println()
	log.Println("只改动内容恰好等于 -from 的记录，其它记录一律不动。")
	log.Println("各服务商改指后的目标取自各自配置（CF_TARGET / ALI_DNS_TARGET / ALI_ESA_TARGET）。")
	log.Println("目前支持批量改指的服务商：cloudflare、esa。")
}

// runSyncDNS 把存量记录从旧目标批量改指到当前配置的目标。
//
// 默认只预览，必须显式加 -apply 才会真正写入 —— 这是一次批量生产 DNS 变更。
func runSyncDNS(manager *dns.Manager, args []string) int {
	flags := flag.NewFlagSet("sync-dns", flag.ExitOnError)
	from := flags.String("from", "", "要替换掉的旧目标值")
	apply := flags.Bool("apply", false, "真正写入改动；不加时只预览")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}

	if *from == "" {
		printSyncUsage()
		return 2
	}

	if manager.Empty() {
		log.Println("没有已启用的 DNS 服务商，请检查 DNS_PROVIDERS 与相关配置")
		return 1
	}

	dryRun := !*apply
	if dryRun {
		log.Println("预览模式：不会写入任何改动，确认无误后加 -apply 执行。")
	}

	ctx, cancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	defer cancel()

	outcomes := manager.RepointAll(ctx, *from, dryRun)

	total := 0
	failed := false
	for _, outcome := range outcomes {
		for _, record := range outcome.Records {
			total++
			log.Printf("[%s] %s → %s", outcome.Label, record.FQDN, record.Value)
		}
		if outcome.Error != "" {
			failed = true
			log.Printf("[%s] 出错: %s", outcome.Label, outcome.Error)
		}
	}

	switch {
	case failed:
		log.Printf("未全部完成：已处理 %d 条记录，请检查上面的报错。", total)
		return 1
	case dryRun:
		log.Printf("预览完成：共 %d 条记录待改指。", total)
		return 0
	default:
		log.Printf("完成：共改指 %d 条记录。", total)
		return 0
	}
}
