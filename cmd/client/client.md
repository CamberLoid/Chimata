# 想一下大概要怎么写

## 1. 用户管理

1. `chimata user set-main`
   - `... --by-uuid $UUID`
   - `... --by-name $name`
2. `chimata user import-ckks-privatekey / publickey`
   - `... --by-file=/path/to/key`
3. `chimata user get-balance`
   - `(--from-cache)`
   - `--online` <- default

## 2. 交易 `chimata transaction`

1. `... new`
   1. `--encrypt-by={sender,receipt}`
   2. `--amount=(float64)`
   3. `--receipt=$receipt-uuid`
   4. `(--as-user=$user-uuid)`
2. `... confirm`
   1. `--by-uuid=$uuid`
3. `... get`
   1. `--all`
   2. `--by-uuid=$uuid`
