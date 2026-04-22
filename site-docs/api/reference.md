---
title: 交互式 API Reference
description: 使用 Scalar 风格界面浏览 ClawSentry OpenAPI 端点、schema、鉴权、示例和错误码
---

# 交互式 API Reference

本页用于查端点、schema、请求/响应示例和错误码。学习路径请先看 [API 概览](overview.md)。

<div class="cs-callout" markdown>
**阅读路径** 如果你在判断“该调用哪类 API”，先看 [API 概览](overview.md)；如果你已经知道端点，留在本页查字段、schema、示例和错误码。
</div>

!!! info "文档生成策略"
    下面的 OpenAPI artifact 是**文档侧静态产物**，由 route inventory + curated semantic overlay 生成。它不会修改 ClawSentry 运行时 API 行为。

!!! warning "Scalar 资源权衡"
    本阶段不引入新的构建依赖。页面使用 pinned CDN 版本加载 Scalar API Reference；`mkdocs build --strict` 不依赖远程 JS 是否可达。若你的环境无法访问 CDN，请直接查看 [原始 OpenAPI JSON](openapi.json)。

<div id="scalar-api-reference"></div>

<noscript>
  JavaScript 未启用。请打开 <a href="../openapi.json">原始 OpenAPI JSON</a>。
</noscript>

<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.52.5"></script>
<script>
  if (window.Scalar) {
    window.Scalar.createApiReference('#scalar-api-reference', {
      url: '../openapi.json',
      theme: 'purple',
      layout: 'modern',
      hideDownloadButton: false,
      hideModels: false,
      defaultHttpClient: {
        targetKey: 'shell',
        clientKey: 'curl'
      }
    })
  }
</script>

## 快速入口

- [下载 / 查看 OpenAPI JSON](openapi.json)
- [API 覆盖矩阵](api-coverage.json)
- [鉴权与安全](authentication.md)
- [决策端点说明](decisions.md)
- [报表、SSE 与 L3 Advisory](reporting.md)
- [OpenClaw Webhook API](webhooks.md)

## 如何阅读这个 Reference

| 分组 | 适合读者 | 你能查到什么 |
| --- | --- | --- |
| AHP 决策 | 二次开发者 | `/ahp`、`/ahp/a3s`、`/ahp/codex`、`/ahp/resolve` 的请求/响应结构 |
| 报表与监控 | 运维 / 前端 | 会话、风险、告警、SSE 事件流 |
| L3 Advisory | 运维 / 安全审查 | snapshot、job、review、full-review 的 advisory-only 边界 |
| Webhook | OpenClaw 集成方 | token、HMAC、timestamp、IP allowlist、idempotency 行为 |
