// Package procpath asks the kernel for a running process's executable path.
//
// The agent's process table knows only the processes it saw exec, so a process that started before the agent did (a long-lived
// XPC service after an agent restart or upgrade, say) is missing from it. This is the fallback for those, used where a decision
// depends on a live parent. It answers only for a process that is still running.
package procpath
