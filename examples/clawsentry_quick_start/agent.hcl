# Local development config template (sanitized)
# Fill your real key locally before running.
default_model = "openai/kimi-k2.5"

providers {
  name     = "openai"
  api_key  = "YOUR_OPENAI_API_KEY"
  base_url = "https://api.openai.com/v1"

  models {
    id        = "kimi-k2.5"
    name      = "kimi-k2.5"
    tool_call = true
  }
}
