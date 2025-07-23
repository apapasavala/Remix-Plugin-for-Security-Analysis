(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-invalid-score (err u103))
(define-constant err-insufficient-balance (err u104))
(define-constant err-invalid-vulnerability (err u105))

(define-data-var next-analysis-id uint u1)
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
