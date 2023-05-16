package main

import "time"

var (
	OperationTxCreateBySender  int64 = 0
	OperationTxCreateByReceipt int64 = 0
	OperationTxConfirm         int64 = 0
)

var (
	DurationDatabaseOpr time.Duration = 0
)
