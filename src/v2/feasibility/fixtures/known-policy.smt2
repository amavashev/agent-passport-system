; APS feasibility obligation
; ir-version 1.0.0
; source-hash e67db563daca15064f891639ef605686d16dcd5ae40a057ccc0783cb8428ebe8
; This script states the obligation. It does not decide it.
(set-logic QF_SLIA)
(declare-const action_scope String)
(declare-const action_spend Int)
(declare-const cumulative_spend Int)
(declare-const current_depth Int)
(declare-const max_depth Int)
(declare-const not_revoked Bool)
(declare-const spend_limit Int)
(declare-const spent_amount Int)
(declare-const within_window Bool)
(assert (= cumulative_spend 15)) ; cumulative_spend_def
(assert not_revoked) ; delegation_active
(assert (<= current_depth max_depth)) ; depth_within_bound
(assert (or (= action_scope "commerce:checkout") (= action_scope "data:read") (= action_scope "data:write"))) ; scope_granted
(assert (<= cumulative_spend spend_limit)) ; spend_within_limit
(assert within_window) ; within_validity_window
(check-sat)
