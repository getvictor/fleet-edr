package main

// The heartbeat goroutine moved to agent/receiver/loop.go (Loop.runHeartbeat). Its tests moved to agent/receiver/heartbeat_test.go.
// This file is kept as a stub so a stray import of the prior symbols would surface as a build error here rather than a silent miss;
// once a tree-wide sweep confirms no caller references runXPCHeartbeat / xpcHeartbeatConfig / xpcPinger, this file should be removed.
