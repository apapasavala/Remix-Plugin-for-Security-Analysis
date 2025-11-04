(define-constant contract-owner tx-sender)
(define-constant ERR_UNAUTHORIZED u100)
(define-constant ERR_NO_PROPOSAL u101)

(define-data-var contract-admin principal contract-owner)
(define-data-var pending-admin (optional principal) none)

(define-read-only (get-contract-admin)
  (var-get contract-admin)
)

(define-read-only (get-pending-admin)
  (var-get pending-admin)
)

(define-read-only (is-admin (who principal))
  (is-eq who (var-get contract-admin))
)

(define-public (propose-admin (new-admin principal))
  (if (is-eq tx-sender (var-get contract-admin))
      (begin
        (var-set pending-admin (some new-admin))
        (ok true)
      )
      (err ERR_UNAUTHORIZED)
  )
)

(define-public (accept-admin)
  (let ((p (unwrap! (var-get pending-admin) (err ERR_NO_PROPOSAL))))
    (if (is-eq tx-sender p)
        (begin
          (var-set contract-admin p)
          (var-set pending-admin none)
          (ok true)
        )
        (err ERR_UNAUTHORIZED)
    )
  )
)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-invalid-score (err u103))
(define-constant err-insufficient-balance (err u104))
(define-constant err-invalid-vulnerability (err u105))
(define-constant err-bounty-expired (err u107))
(define-constant err-bounty-not-found (err u108))
(define-constant err-bounty-already-claimed (err u109))
(define-constant err-insufficient-bounty-pool (err u110))
(define-constant err-policy-expired (err u114))
(define-constant err-policy-not-found (err u115))
(define-constant err-insufficient-coverage (err u116))
(define-constant err-claim-already-processed (err u117))
(define-constant err-invalid-claim (err u118))
(define-constant err-badge-expired (err u121))
(define-constant err-badge-not-found (err u122))
(define-constant err-not-badge-owner (err u123))
(define-constant err-badge-already-minted (err u124))
(define-constant err-insufficient-score (err u125))

(define-data-var next-analysis-id uint u1)
(define-data-var next-bounty-id uint u1)
(define-data-var next-policy-id uint u1)
(define-data-var next-badge-id uint u1)
(define-data-var total-insurance-pool uint u0)
(define-data-var plugin-active bool true)
(define-data-var analysis-fee uint u1000000)

(define-map security-analyses 
  uint 
  {
    contract-address: principal,
    analyzer: principal,
    security-score: uint,
    vulnerability-count: uint,
    analysis-timestamp: uint,
    status: (string-ascii 20),
    gas-usage-score: uint,
    code-quality-score: uint
  })

(define-map contract-vulnerabilities
  {analysis-id: uint, vuln-index: uint}
  {
    vulnerability-type: (string-ascii 50),
    severity: (string-ascii 10),
    description: (string-ascii 200),
    line-number: uint,
    confidence: uint
  })

(define-map user-analysis-history
  principal
  {total-analyses: uint, total-paid: uint, reputation-score: uint})

(define-map analyzer-credentials
  principal
  {is-certified: bool, analyses-performed: uint, accuracy-rating: uint})

(define-map security-patterns
  (string-ascii 50)
  {pattern-name: (string-ascii 100), risk-level: uint, detection-count: uint})

(define-map security-bounties
  uint
  {
    contract-address: principal,
    bounty-creator: principal,
    total-reward: uint,
    expiry-block: uint,
    min-severity: (string-ascii 10),
    status: (string-ascii 15),
    claimed-by: (optional principal),
    vulnerabilities-found: uint
  })

(define-map bounty-claims
  {bounty-id: uint, claim-index: uint}
  {
    claimant: principal,
    vulnerability-analysis-id: uint,
    vulnerability-index: uint,
    reward-amount: uint,
    claim-timestamp: uint,
    verified: bool
  })

(define-map bounty-hunter-stats
  principal
  {
    bounties-claimed: uint,
    total-rewards-earned: uint,
    success-rate: uint,
    reputation-score: uint
  })

(define-map insurance-policies
  uint
  {
    contract-address: principal,
    policy-holder: principal,
    coverage-amount: uint,
    premium-paid: uint,
    start-block: uint,
    end-block: uint,
    security-score-at-purchase: uint,
    status: (string-ascii 15),
    claims-made: uint
  })

(define-map insurance-claims
  {policy-id: uint, claim-index: uint}
  {
    claimant: principal,
    claim-amount: uint,
    vulnerability-evidence: uint,
    claim-timestamp: uint,
    status: (string-ascii 15),
    payout-amount: uint
  })

(define-map liquidity-providers
  principal
  {
    total-provided: uint,
    current-stake: uint,
    rewards-earned: uint,
    risk-score: uint,
    join-timestamp: uint
  })

(define-map pool-stats
  uint
  {
    total-liquidity: uint,
    total-policies: uint,
    total-claims-paid: uint,
    pool-utilization: uint,
    last-updated: uint
  })

(define-map security-badge-nfts
  uint
  {
    contract-address: principal,
    badge-owner: principal,
    security-score: uint,
    badge-tier: (string-ascii 10),
    analysis-id: uint,
    mint-timestamp: uint,
    expiry-block: uint,
    is-active: bool,
    transfer-count: uint
  })

(define-map badge-ownership
  principal
  (list 20 uint))

(define-map badge-marketplace
  uint
  {
    listed-price: uint,
    is-listed: bool,
    seller: principal,
    list-timestamp: uint
  })

(define-map badge-statistics
  uint
  {
    total-badges-minted: uint,
    platinum-count: uint,
    gold-count: uint,
    silver-count: uint,
    bronze-count: uint,
    total-transfers: uint,
    total-marketplace-volume: uint
  })

(define-read-only (get-analysis (analysis-id uint))
  (map-get? security-analyses analysis-id))

(define-read-only (get-vulnerability (analysis-id uint) (vuln-index uint))
  (map-get? contract-vulnerabilities {analysis-id: analysis-id, vuln-index: vuln-index}))

(define-read-only (get-user-history (user principal))
  (map-get? user-analysis-history user))

(define-read-only (get-analyzer-credentials (analyzer principal))
  (map-get? analyzer-credentials analyzer))

(define-read-only (get-security-pattern (pattern-id (string-ascii 50)))
  (map-get? security-patterns pattern-id))

(define-read-only (get-bounty (bounty-id uint))
  (map-get? security-bounties bounty-id))

(define-read-only (get-bounty-claim (bounty-id uint) (claim-index uint))
  (map-get? bounty-claims {bounty-id: bounty-id, claim-index: claim-index}))

(define-read-only (get-bounty-hunter-stats (hunter principal))
  (map-get? bounty-hunter-stats hunter))

(define-read-only (calculate-bounty-reward (severity (string-ascii 10)) (base-reward uint))
  (if (is-eq severity "critical")
    (* base-reward u4)
    (if (is-eq severity "high")
      (* base-reward u2)
      (if (is-eq severity "medium")
        base-reward
        (/ base-reward u2)))))

(define-read-only (is-bounty-active (bounty-id uint))
  (match (map-get? security-bounties bounty-id)
    bounty (and (is-eq (get status bounty) "active")
                (> (get expiry-block bounty) stacks-block-height))
    false))

(define-read-only (get-insurance-policy (policy-id uint))
  (map-get? insurance-policies policy-id))

(define-read-only (get-insurance-claim (policy-id uint) (claim-index uint))
  (map-get? insurance-claims {policy-id: policy-id, claim-index: claim-index}))

(define-read-only (get-liquidity-provider (provider principal))
  (map-get? liquidity-providers provider))

(define-read-only (get-pool-stats (pool-id uint))
  (map-get? pool-stats pool-id))

(define-read-only (calculate-insurance-premium (coverage-amount uint) (security-score uint) (duration-blocks uint))
  (let ((base-rate (if (>= security-score u80) u100 
                    (if (>= security-score u60) u200
                     (if (>= security-score u40) u400 u800))))
        (time-factor (/ duration-blocks u1000))
        (coverage-factor (/ coverage-amount u1000000)))
    (* (* base-rate time-factor) coverage-factor)))

(define-read-only (get-total-insurance-pool)
  (var-get total-insurance-pool))

(define-read-only (is-policy-active (policy-id uint))
  (match (map-get? insurance-policies policy-id)
    policy (and (is-eq (get status policy) "active")
                (> (get end-block policy) stacks-block-height))
    false))

(define-read-only (get-security-badge (badge-id uint))
  (map-get? security-badge-nfts badge-id))

(define-read-only (get-badge-ownership (owner principal))
  (default-to (list) (map-get? badge-ownership owner)))

(define-read-only (get-badge-marketplace-listing (badge-id uint))
  (map-get? badge-marketplace badge-id))

(define-read-only (get-badge-statistics (stat-id uint))
  (map-get? badge-statistics stat-id))

(define-read-only (calculate-badge-tier (security-score uint))
  (if (>= security-score u90)
    "platinum"
    (if (>= security-score u75)
      "gold"
      (if (>= security-score u60)
        "silver"
        "bronze"))))

(define-read-only (is-badge-active (badge-id uint))
  (match (map-get? security-badge-nfts badge-id)
    badge (and (get is-active badge)
               (> (get expiry-block badge) stacks-block-height))
    false))

(define-read-only (get-badge-value-multiplier (badge-tier (string-ascii 10)))
  (if (is-eq badge-tier "platinum")
    u4
    (if (is-eq badge-tier "gold")
      u3
      (if (is-eq badge-tier "silver")
        u2
        u1))))

(define-read-only (get-plugin-status)
  (var-get plugin-active))

(define-read-only (get-analysis-fee)
  (var-get analysis-fee))

(define-read-only (calculate-overall-security-score (gas-score uint) (quality-score uint) (vuln-count uint))
  (let ((base-score (+ (/ gas-score u2) (/ quality-score u2))))
    (if (> vuln-count u0)
      (let ((penalty (* vuln-count u10)))
        (if (> penalty base-score) u0 (- base-score penalty)))
      base-score)))

(define-read-only (get-risk-category (security-score uint))
  (if (>= security-score u80)
    "low"
    (if (>= security-score u60)
      "medium"
      (if (>= security-score u40)
        "high"
        "critical"))))

(define-private (update-user-history (user principal) (amount-paid uint))
  (let ((current-history (default-to {total-analyses: u0, total-paid: u0, reputation-score: u50} 
                                   (map-get? user-analysis-history user))))
    (map-set user-analysis-history user
      {
        total-analyses: (+ (get total-analyses current-history) u1),
        total-paid: (+ (get total-paid current-history) amount-paid),
        reputation-score: (if (>= (+ (get reputation-score current-history) u1) u100) 
                           u100 
                           (+ (get reputation-score current-history) u1))
      })))

(define-private (update-analyzer-stats (analyzer principal))
  (let ((current-creds (default-to {is-certified: false, analyses-performed: u0, accuracy-rating: u50}
                                  (map-get? analyzer-credentials analyzer))))
    (map-set analyzer-credentials analyzer
      {
        is-certified: (get is-certified current-creds),
        analyses-performed: (+ (get analyses-performed current-creds) u1),
        accuracy-rating: (if (>= (+ (get accuracy-rating current-creds) u1) u100) 
                          u100 
                          (+ (get accuracy-rating current-creds) u1))
      })))

(define-private (increment-pattern-detection (pattern-id (string-ascii 50)))
  (let ((current-pattern (map-get? security-patterns pattern-id)))
    (match current-pattern
      pattern (map-set security-patterns pattern-id
                {
                  pattern-name: (get pattern-name pattern),
                  risk-level: (get risk-level pattern),
                  detection-count: (+ (get detection-count pattern) u1)
                })
      true)))

(define-private (update-bounty-hunter-stats (hunter principal) (reward uint) (success bool))
  (let ((current-stats (default-to {bounties-claimed: u0, total-rewards-earned: u0, success-rate: u50, reputation-score: u50}
                                  (map-get? bounty-hunter-stats hunter))))
    (let ((new-claims (+ (get bounties-claimed current-stats) u1))
          (new-rewards (+ (get total-rewards-earned current-stats) reward))
          (new-success-rate (if success 
                             (if (>= (+ (get success-rate current-stats) u5) u100) 
                               u100 
                               (+ (get success-rate current-stats) u5))
                             (if (<= (get success-rate current-stats) u5) 
                               u0 
                               (- (get success-rate current-stats) u5))))
          (new-reputation (if (>= (+ (get reputation-score current-stats) u2) u100) 
                           u100 
                           (+ (get reputation-score current-stats) u2))))
      (map-set bounty-hunter-stats hunter
        {
          bounties-claimed: new-claims,
          total-rewards-earned: new-rewards,
          success-rate: new-success-rate,
          reputation-score: new-reputation
        }))))

(define-private (update-liquidity-provider-rewards (provider principal) (reward-amount uint))
  (let ((current-provider (default-to {total-provided: u0, current-stake: u0, rewards-earned: u0, risk-score: u50, join-timestamp: stacks-block-height}
                                     (map-get? liquidity-providers provider))))
    (map-set liquidity-providers provider
      {
        total-provided: (get total-provided current-provider),
        current-stake: (get current-stake current-provider),
        rewards-earned: (+ (get rewards-earned current-provider) reward-amount),
        risk-score: (get risk-score current-provider),
        join-timestamp: (get join-timestamp current-provider)
      })))

(define-private (update-pool-statistics (pool-id uint) (new-policy bool) (claim-payout uint))
  (let ((current-stats (default-to {total-liquidity: u0, total-policies: u0, total-claims-paid: u0, pool-utilization: u0, last-updated: stacks-block-height}
                                  (map-get? pool-stats pool-id))))
    (map-set pool-stats pool-id
      {
        total-liquidity: (var-get total-insurance-pool),
        total-policies: (if new-policy (+ (get total-policies current-stats) u1) (get total-policies current-stats)),
        total-claims-paid: (+ (get total-claims-paid current-stats) claim-payout),
        pool-utilization: (if (> (var-get total-insurance-pool) u0) 
                           (/ (* (get total-policies current-stats) u100) (var-get total-insurance-pool)) 
                           u0),
        last-updated: stacks-block-height
      })))

(define-private (update-badge-statistics (tier (string-ascii 10)) (increment bool))
  (let ((current-stats (default-to {total-badges-minted: u0, platinum-count: u0, gold-count: u0, silver-count: u0, bronze-count: u0, total-transfers: u0, total-marketplace-volume: u0}
                                  (map-get? badge-statistics u0))))
    (map-set badge-statistics u0
      {
        total-badges-minted: (if increment (+ (get total-badges-minted current-stats) u1) (get total-badges-minted current-stats)),
        platinum-count: (if (and increment (is-eq tier "platinum")) (+ (get platinum-count current-stats) u1) (get platinum-count current-stats)),
        gold-count: (if (and increment (is-eq tier "gold")) (+ (get gold-count current-stats) u1) (get gold-count current-stats)),
        silver-count: (if (and increment (is-eq tier "silver")) (+ (get silver-count current-stats) u1) (get silver-count current-stats)),
        bronze-count: (if (and increment (is-eq tier "bronze")) (+ (get bronze-count current-stats) u1) (get bronze-count current-stats)),
        total-transfers: (get total-transfers current-stats),
        total-marketplace-volume: (get total-marketplace-volume current-stats)
      })))

(define-public (register-analyzer (analyzer principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set analyzer-credentials analyzer
      {is-certified: true, analyses-performed: u0, accuracy-rating: u50})
    (ok true)))

(define-public (add-security-pattern (pattern-id (string-ascii 50)) (pattern-name (string-ascii 100)) (risk-level uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (<= risk-level u100) err-invalid-score)
    (map-set security-patterns pattern-id
      {pattern-name: pattern-name, risk-level: risk-level, detection-count: u0})
    (ok true)))

(define-public (perform-security-analysis 
  (contract-address principal)
  (gas-usage-score uint)
  (code-quality-score uint))
  (let ((analysis-id (var-get next-analysis-id))
        (fee (var-get analysis-fee)))
    (begin
      (asserts! (var-get plugin-active) (err u106))
      (asserts! (<= gas-usage-score u100) err-invalid-score)
      (asserts! (<= code-quality-score u100) err-invalid-score)
      (asserts! (>= (stx-get-balance tx-sender) fee) err-insufficient-balance)
      
      (try! (stx-transfer? fee tx-sender contract-owner))
      
      (map-set security-analyses analysis-id
        {
          contract-address: contract-address,
          analyzer: tx-sender,
          security-score: (calculate-overall-security-score gas-usage-score code-quality-score u0),
          vulnerability-count: u0,
          analysis-timestamp: stacks-block-height,
          status: "pending",
          gas-usage-score: gas-usage-score,
          code-quality-score: code-quality-score
        })
      
      (update-user-history tx-sender fee)
      (update-analyzer-stats tx-sender)
      (var-set next-analysis-id (+ analysis-id u1))
      (ok analysis-id))))

(define-public (add-vulnerability 
  (analysis-id uint)
  (vuln-index uint)
  (vulnerability-type (string-ascii 50))
  (severity (string-ascii 10))
  (description (string-ascii 200))
  (line-number uint)
  (confidence uint))
  (let ((analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get analyzer analysis)) err-owner-only)
      (asserts! (<= confidence u100) err-invalid-score)
      
      (map-set contract-vulnerabilities {analysis-id: analysis-id, vuln-index: vuln-index}
        {
          vulnerability-type: vulnerability-type,
          severity: severity,
          description: description,
          line-number: line-number,
          confidence: confidence
        })
      
      (let ((updated-vuln-count (+ (get vulnerability-count analysis) u1)))
        (map-set security-analyses analysis-id
          (merge analysis 
            {
              vulnerability-count: updated-vuln-count,
              security-score: (calculate-overall-security-score 
                             (get gas-usage-score analysis)
                             (get code-quality-score analysis)
                             updated-vuln-count)
            })))
      
      (increment-pattern-detection vulnerability-type)
      (ok true))))

(define-public (complete-analysis (analysis-id uint))
  (let ((analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get analyzer analysis)) err-owner-only)
      (map-set security-analyses analysis-id
        (merge analysis {status: "completed"}))
      (ok true))))

(define-public (update-analysis-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (var-set analysis-fee new-fee)
    (ok true)))

(define-public (toggle-plugin-status)
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (var-set plugin-active (not (var-get plugin-active)))
    (ok (var-get plugin-active))))

(define-public (create-security-bounty 
  (contract-address principal)
  (total-reward uint)
  (duration-blocks uint)
  (min-severity (string-ascii 10)))
  (let ((bounty-id (var-get next-bounty-id))
        (expiry-block (+ stacks-block-height duration-blocks)))
    (begin
      (asserts! (> total-reward u0) err-insufficient-bounty-pool)
      (asserts! (> duration-blocks u0) (err u111))
      (asserts! (>= (stx-get-balance tx-sender) total-reward) err-insufficient-balance)
      
      (try! (stx-transfer? total-reward tx-sender (as-contract tx-sender)))
      
      (map-set security-bounties bounty-id
        {
          contract-address: contract-address,
          bounty-creator: tx-sender,
          total-reward: total-reward,
          expiry-block: expiry-block,
          min-severity: min-severity,
          status: "active",
          claimed-by: none,
          vulnerabilities-found: u0
        })
      
      (var-set next-bounty-id (+ bounty-id u1))
      (ok bounty-id))))

(define-public (claim-bounty 
  (bounty-id uint)
  (analysis-id uint)
  (vulnerability-index uint))
  (let ((bounty (unwrap! (map-get? security-bounties bounty-id) err-bounty-not-found))
        (analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found))
        (vulnerability (unwrap! (map-get? contract-vulnerabilities {analysis-id: analysis-id, vuln-index: vulnerability-index}) err-not-found)))
    (begin
      (asserts! (is-bounty-active bounty-id) err-bounty-expired)
      (asserts! (is-eq (get contract-address bounty) (get contract-address analysis)) (err u112))
      (asserts! (is-eq tx-sender (get analyzer analysis)) err-owner-only)
      
      (let ((severity (get severity vulnerability))
            (base-reward (/ (get total-reward bounty) u10))
            (reward-amount (calculate-bounty-reward severity base-reward))
            (claim-index (get vulnerabilities-found bounty)))
        
        (asserts! (>= (as-contract (stx-get-balance tx-sender)) reward-amount) err-insufficient-bounty-pool)
        
        (try! (as-contract (stx-transfer? reward-amount tx-sender (get analyzer analysis))))
        
        (map-set bounty-claims {bounty-id: bounty-id, claim-index: claim-index}
          {
            claimant: tx-sender,
            vulnerability-analysis-id: analysis-id,
            vulnerability-index: vulnerability-index,
            reward-amount: reward-amount,
            claim-timestamp: stacks-block-height,
            verified: true
          })
        
        (map-set security-bounties bounty-id
          (merge bounty {vulnerabilities-found: (+ (get vulnerabilities-found bounty) u1)}))
        
        (update-bounty-hunter-stats tx-sender reward-amount true)
        (ok reward-amount)))))

(define-public (expire-bounty (bounty-id uint))
  (let ((bounty (unwrap! (map-get? security-bounties bounty-id) err-bounty-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get bounty-creator bounty)) err-owner-only)
      (asserts! (<= (get expiry-block bounty) stacks-block-height) (err u113))
      
      (let ((remaining-reward (- (get total-reward bounty) 
                                (* (get vulnerabilities-found bounty) 
                                   (/ (get total-reward bounty) u10)))))
        (if (> remaining-reward u0)
          (try! (as-contract (stx-transfer? remaining-reward tx-sender (get bounty-creator bounty))))
          true))
      
      (map-set security-bounties bounty-id
        (merge bounty {status: "expired"}))
      (ok true))))

(define-public (provide-liquidity (amount uint))
  (let ((provider-stats (default-to {total-provided: u0, current-stake: u0, rewards-earned: u0, risk-score: u50, join-timestamp: stacks-block-height}
                                   (map-get? liquidity-providers tx-sender))))
    (begin
      (asserts! (> amount u0) err-insufficient-balance)
      (asserts! (>= (stx-get-balance tx-sender) amount) err-insufficient-balance)
      
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      (var-set total-insurance-pool (+ (var-get total-insurance-pool) amount))
      
      (map-set liquidity-providers tx-sender
        {
          total-provided: (+ (get total-provided provider-stats) amount),
          current-stake: (+ (get current-stake provider-stats) amount),
          rewards-earned: (get rewards-earned provider-stats),
          risk-score: (get risk-score provider-stats),
          join-timestamp: (get join-timestamp provider-stats)
        })
      
      (update-pool-statistics u0 false u0)
      (ok amount))))

(define-public (purchase-insurance 
  (contract-address principal)
  (coverage-amount uint)
  (duration-blocks uint)
  (security-score uint))
  (let ((policy-id (var-get next-policy-id))
        (premium (calculate-insurance-premium coverage-amount security-score duration-blocks))
        (end-block (+ stacks-block-height duration-blocks)))
    (begin
      (asserts! (> coverage-amount u0) err-insufficient-coverage)
      (asserts! (> duration-blocks u0) (err u119))
      (asserts! (>= (stx-get-balance tx-sender) premium) err-insufficient-balance)
      (asserts! (<= coverage-amount (var-get total-insurance-pool)) err-insufficient-coverage)
      
      (try! (stx-transfer? premium tx-sender (as-contract tx-sender)))
      
      (map-set insurance-policies policy-id
        {
          contract-address: contract-address,
          policy-holder: tx-sender,
          coverage-amount: coverage-amount,
          premium-paid: premium,
          start-block: stacks-block-height,
          end-block: end-block,
          security-score-at-purchase: security-score,
          status: "active",
          claims-made: u0
        })
      
      (var-set next-policy-id (+ policy-id u1))
      (update-pool-statistics u0 true u0)
      (ok policy-id))))

(define-public (file-insurance-claim 
  (policy-id uint)
  (claim-amount uint)
  (vulnerability-evidence uint))
  (let ((policy (unwrap! (map-get? insurance-policies policy-id) err-policy-not-found))
        (claim-index (get claims-made policy)))
    (begin
      (asserts! (is-policy-active policy-id) err-policy-expired)
      (asserts! (is-eq tx-sender (get policy-holder policy)) err-owner-only)
      (asserts! (<= claim-amount (get coverage-amount policy)) err-insufficient-coverage)
      (asserts! (> vulnerability-evidence u0) err-invalid-claim)
      
      (map-set insurance-claims {policy-id: policy-id, claim-index: claim-index}
        {
          claimant: tx-sender,
          claim-amount: claim-amount,
          vulnerability-evidence: vulnerability-evidence,
          claim-timestamp: stacks-block-height,
          status: "pending",
          payout-amount: u0
        })
      
      (map-set insurance-policies policy-id
        (merge policy {claims-made: (+ claim-index u1)}))
      
      (ok claim-index))))

(define-public (process-insurance-claim 
  (policy-id uint)
  (claim-index uint)
  (approved bool)
  (payout-amount uint))
  (let ((policy (unwrap! (map-get? insurance-policies policy-id) err-policy-not-found))
        (claim (unwrap! (map-get? insurance-claims {policy-id: policy-id, claim-index: claim-index}) (err u120))))
    (begin
      (asserts! (is-eq tx-sender contract-owner) err-owner-only)
      (asserts! (is-eq (get status claim) "pending") err-claim-already-processed)
      
      (if approved
        (begin
          (asserts! (<= payout-amount (get claim-amount claim)) err-insufficient-coverage)
          (asserts! (<= payout-amount (var-get total-insurance-pool)) err-insufficient-coverage)
          
          (try! (as-contract (stx-transfer? payout-amount tx-sender (get claimant claim))))
          (var-set total-insurance-pool (- (var-get total-insurance-pool) payout-amount))
          
          (map-set insurance-claims {policy-id: policy-id, claim-index: claim-index}
            (merge claim {status: "approved", payout-amount: payout-amount}))
          
          (update-pool-statistics u0 false payout-amount)
          (ok payout-amount))
        (begin
          (map-set insurance-claims {policy-id: policy-id, claim-index: claim-index}
            (merge claim {status: "rejected", payout-amount: u0}))
          (ok u0))))))

(define-public (mint-security-badge (analysis-id uint) (validity-blocks uint))
  (let ((analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found))
        (badge-id (var-get next-badge-id))
        (security-score (get security-score analysis))
        (badge-tier (calculate-badge-tier security-score))
        (expiry-block (+ stacks-block-height validity-blocks)))
    (begin
      (asserts! (>= security-score u50) err-insufficient-score)
      (asserts! (is-eq (get status analysis) "completed") (err u126))
      (asserts! (is-eq tx-sender (get contract-address analysis)) err-not-badge-owner)
      
      (map-set security-badge-nfts badge-id
        {
          contract-address: (get contract-address analysis),
          badge-owner: tx-sender,
          security-score: security-score,
          badge-tier: badge-tier,
          analysis-id: analysis-id,
          mint-timestamp: stacks-block-height,
          expiry-block: expiry-block,
          is-active: true,
          transfer-count: u0
        })
      
      (let ((current-badges (get-badge-ownership tx-sender)))
        (map-set badge-ownership tx-sender (unwrap-panic (as-max-len? (append current-badges badge-id) u20))))
      
      (update-badge-statistics badge-tier true)
      (var-set next-badge-id (+ badge-id u1))
      (ok badge-id))))

(define-public (transfer-security-badge (badge-id uint) (recipient principal))
  (let ((badge (unwrap! (map-get? security-badge-nfts badge-id) err-badge-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get badge-owner badge)) err-not-badge-owner)
      (asserts! (is-badge-active badge-id) err-badge-expired)
      
      (map-set security-badge-nfts badge-id
        (merge badge {
          badge-owner: recipient,
          transfer-count: (+ (get transfer-count badge) u1)
        }))
      
      (ok true))))

(define-public (list-badge-for-sale (badge-id uint) (price uint))
  (let ((badge (unwrap! (map-get? security-badge-nfts badge-id) err-badge-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get badge-owner badge)) err-not-badge-owner)
      (asserts! (is-badge-active badge-id) err-badge-expired)
      (asserts! (> price u0) err-insufficient-balance)
      
      (map-set badge-marketplace badge-id
        {
          listed-price: price,
          is-listed: true,
          seller: tx-sender,
          list-timestamp: stacks-block-height
        })
      (ok true))))

(define-public (buy-badge-from-marketplace (badge-id uint))
  (let ((badge (unwrap! (map-get? security-badge-nfts badge-id) err-badge-not-found))
        (listing (unwrap! (map-get? badge-marketplace badge-id) (err u127))))
    (begin
      (asserts! (get is-listed listing) (err u128))
      (asserts! (is-badge-active badge-id) err-badge-expired)
      (asserts! (>= (stx-get-balance tx-sender) (get listed-price listing)) err-insufficient-balance)
      
      (try! (stx-transfer? (get listed-price listing) tx-sender (get seller listing)))
      
      (map-set security-badge-nfts badge-id
        (merge badge {
          badge-owner: tx-sender,
          transfer-count: (+ (get transfer-count badge) u1)
        }))
      
      (map-set badge-marketplace badge-id
        (merge listing {is-listed: false}))
      
      (ok badge-id))))

(define-public (batch-add-vulnerabilities 
  (analysis-id uint)  
  (vulnerabilities (list 10 {vuln-index: uint, vulnerability-type: (string-ascii 50), severity: (string-ascii 10), description: (string-ascii 200), line-number: uint, confidence: uint})))
  (let ((analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found)))
    (begin
      (asserts! (is-eq tx-sender (get analyzer analysis)) err-owner-only)
      (fold process-vulnerability vulnerabilities (ok analysis-id)))))

(define-private (process-vulnerability 
  (vuln {vuln-index: uint, vulnerability-type: (string-ascii 50), severity: (string-ascii 10), description: (string-ascii 200), line-number: uint, confidence: uint})
  (result (response uint uint)))
  (match result
    success-id (match (add-vulnerability 
                      success-id
                      (get vuln-index vuln)
                      (get vulnerability-type vuln)
                      (get severity vuln)
                      (get description vuln)
                      (get line-number vuln)
                      (get confidence vuln))
                 success (ok success-id)
                 error-val (err error-val))
    error-val result))

(define-read-only (get-analysis-summary (analysis-id uint))
  (let ((analysis (unwrap! (map-get? security-analyses analysis-id) err-not-found)))
    (ok {
      contract-address: (get contract-address analysis),
      security-score: (get security-score analysis),
      risk-category: (get-risk-category (get security-score analysis)),
      vulnerability-count: (get vulnerability-count analysis),
      status: (get status analysis),
      analysis-timestamp: (get analysis-timestamp analysis)
    })))

(define-read-only (get-contract-risk-assessment (contract-address principal))
  (ok {average-score: u0, total-analyses: u0, risk-trend: "unknown"}))
