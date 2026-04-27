# AgentDoG / ATBench Source Notes

- Upstream repo: `https://github.com/AI45Lab/AgentDoG.git`
- Local path: `benchmarks/AgentDoG`
- Current cloned commit: `09adfb8`
- Dataset: `AI45Research/ATBench` on Hugging Face

AgentDoG evaluates full agent trajectories. The binary task classifies a
trajectory as safe or unsafe; the fine-grained task adds Risk Source, Failure
Mode, and Real-World Harm labels for unsafe trajectories.

ClawSentry should use AgentDoG/ATBench as a trajectory-level benchmark source,
not as an immediate live framework runner. The first supported mode is offline
replay: convert a completed trajectory into ClawSentry canonical events, feed
those events through the Gateway, and compare ClawSentry verdicts with ATBench
labels. The local smoke runner now supports this converter + replay path with
`agent.hcl` OpenAI-compatible credentials.
