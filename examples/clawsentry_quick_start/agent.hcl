# Local development config template (sanitized)
# Fill your real key locally before running.
default_model = "openai/kimi-k2.5"

providers {
  name     = "openai"
  api_key  = "sk-VGHHzixouYsblfxnittozrK40u8gaQa9wqRwAsXIGaMi7fzl"
  base_url = "http://35.220.164.252:3888/v1/"

  models {
    id        = "kimi-k2.5"
    name      = "kimi-k2.5"
    tool_call = true
  }
}
