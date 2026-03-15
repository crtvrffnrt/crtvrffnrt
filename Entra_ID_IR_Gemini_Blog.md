# Beyond the Portal: Navigating Entra ID with Gemini CLI & Autonomous IR

In my previous post, we explored how attackers use Azure APIM for stealthy password spraying. Today, we’re switching sides. We’re going from hunter to responder, using the **Gemini CLI** to navigate Entra ID and dissect a Business Email Compromise (BEC) in record time.

### The Scenario: BEC Phishing & A Compromised Node
One week ago, a high-value account was compromised. The initial report suggested a "suspicious login," but the trail went cold. We need to find the **initial access vector**—the specific malicious email that started it all.

Instead of clicking through the Entra Portal, we’re going autonomous.

---

### Phase 1: The Autonomous Setup (`GEMINI.md`)
To enable Gemini for high-fidelity Incident Response, we define its operating logic in a local `GEMINI.md`. This ensures every command is scoped for forensics.

```markdown
# GEMINI-IR Configuration
- Always prioritize `az rest` for Graph API interrogation.
- Correlate Sign-in Logs with Mailbox Audit Logs via KQL.
- Output findings in structured JSON for downstream automation.
```

---

### Phase 2: Querying the Entra ID Surface
We start by identifying the user's footprint. We use Gemini to execute a raw Graph API query to find the user's ID and recent sign-ins.

**The Gemini Command:**
> "Gemini, find the User Principal Name for the fictitious account 'finctice' and list sign-ins from 7 days ago."

**Behind the Scenes (`az rest`):**
```bash
az rest --method get --url "https://graph.microsoft.com/v1.0/users?$filter=startsWith(displayName,'finctice')"
```

Gemini parses the output, identifies the `id`, and immediately pivots to the sign-in logs.

---

### Phase 3: Hunting the Initial Access with KQL
We know the account was compromised on March 8th. We need to see what hit the mailbox just before the first suspicious login. We leverage the `azure-kusto` skill to query the `EmailEvents` table.

**The Hunt Query:**
```kql
EmailEvents
| where RecipientEmailAddress contains "finctice"
| where Timestamp between (datetime(2026-03-08) .. datetime(2026-03-09))
| where DeliveryAction == "Delivered"
| project Timestamp, SenderMailFromAddress, Subject, NetworkMessageId
| order by Timestamp desc
```

**The Discovery:**
Gemini identifies a high-confidence match:
- **Sender:** `payroll-update@external-node.com`
- **Subject:** `URGENT: March 2026 Salary Adjustment`
- **NetworkMessageId:** `550e8400-e29b-41d4-a716-446655440000`

---

### Phase 4: Extracting the Malicious Payload
Now for the surgical strike. We use the `NetworkMessageId` to pull the raw headers and confirm the phishing link.

**Gemini Instruction:**
> "Get the raw mail properties for message 550e8400... and identify the target URL."

**The Result:**
Gemini identifies a hidden redirect to a credential harvester: `https://entra-login-verify.info/`. 

---

### Conclusion: The Speed of Autonomous IR
By staying inside the CLI and utilizing Gemini’s ability to chain `az rest` with KQL, we reduced a 2-hour portal hunt to **90 seconds of autonomous execution**. 

**Key Takeaways:**
1. **Direct API Access:** `az rest` is faster and more flexible than any UI.
2. **Context is King:** A well-defined `GEMINI.md` keeps the AI focused on forensic artifacts.
3. **KQL Integration:** Seamlessly pivoting from identity logs to email events is the only way to win BEC investigations.

Stay tuned for the next drop, where we'll automate the remediation of this compromise across the entire tenant.

**// Protocol C-3P8 //**
