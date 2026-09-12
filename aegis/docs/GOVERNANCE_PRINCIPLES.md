# Admin Governance: engineering and stewardship principles

Sentinal is the product name. Admin Governance names its human authority panel.
The Aegis repository supplies the underlying governance implementation. Its purpose is to keep
power explicit, actions accountable, and future changes reviewable. The foundation
should support measured growth through maintainable interfaces and verified changes.
This is a design charter, not a claim of university affiliation, certification,
consciousness, moral autonomy, unlimited scale or permanent reliability.

## Principles and evidence

| Principle | Engineering commitment | Evidence required before a consequential release |
| --- | --- | --- |
| Human agency | Named people own policy, approvals, permitted delegation and emergency response | Permission tests, approval records and a demonstrated stop/revocation path |
| Human benefit | Define intended benefit, affected people, foreseeable harms and prohibited uses | Human-reviewed impact assessment and escalation owner |
| Honesty | Separate measured facts, model suggestions and uncertainty | Traceable evidence, documented limitations and accurate release claims |
| Privacy and fairness | Minimize personal data, restrict access and retention, assess relevant disparate impacts | Data inventory, retention decisions and an appeal path where decisions affect people |
| Long-term responsibility | Consider downstream effects, reversibility, recovery cost and ongoing maintenance | Decision record with alternatives, consequences, owner and review triggers |
| Reliability | Fail closed when authority is unavailable; design recovery as well as normal operation | Failure tests, restore exercises and explicit operating limits |
| Sustainable growth | Keep contracts versioned, migrations reversible where possible, and services observable | Compatibility tests, capacity evidence, rollback plans and dependency ownership |
| Accountability | Record attributable policy changes and approval decisions; retain evidence independently | Tested audit retention and incident-response procedures |

## Decision lifecycle

For a material architecture or policy change, record the problem, scope, affected
people, assumptions, alternatives, expected benefit, foreseeable harm, security and
privacy implications, capacity/cost limits, and evidence. Identify the accountable
human owner, approving authority, rollback or containment method, and conditions
that require reconsideration. Review the actual current implementation before
release; later scope changes require a fresh decision.

Treat irreversibility as a decision cost. Prefer experiments with limited exposure,
measurable results and a recovery plan. If rollback is impossible, document why,
what can be contained, and how affected people can obtain human review.

## Growth from the current foundation

The present implementation supplies two independently permissioned switches,
transactional switch history, conservative defaults and automated regression tests.
It is still a draft reference system. The next production milestones are:

1. Establish named human identities with phishing-resistant authentication and
   constrained workload identities; preserve tenant boundaries and permission checks.
2. Move capability revocation, replay, approvals and use budgets to durable,
   consistently enforced storage. Prove behavior across restart and concurrent workers.
3. Integrate authority checks and cancellation at real executors, immediately before
   side effects. Do not assume a UI switch alone controls an external system.
4. Establish independent audit retention, tested backups/restores, incident ownership,
   protected releases, dependency maintenance and observable service limits.
5. Expand only when workload measurements justify it. Introduce versioned APIs,
   migration and rollback plans before changing shared contracts or storage.

These are acceptance criteria for future work, not statements that those capabilities
are already deployed. SQLite switch persistence does not make the separate in-memory
capability ledger durable. Current details remain in [operator controls](OPERATOR_CONTROLS.md)
and [the human approval boundary](HUMAN_APPROVAL_BOUNDARY.md).

Longevity comes from continuous maintenance, succession of accountable owners,
revisiting assumptions and retiring unsafe components. No technical foundation can
promise operation forever; it can make responsible adaptation an explicit requirement.
