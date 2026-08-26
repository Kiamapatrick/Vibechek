from dataclasses import dataclass

from vibeshield.models.finding import Finding
from vibeshield.triage.models import ContextSnippet


@dataclass(frozen=True)
class PromptTemplate:
    """Typed prompt template for LLM triage."""
    version: str
    system: str
    user_template: str
    
    def build(self, finding: Finding, context: list[ContextSnippet]) -> str:
        """Build the user prompt with finding and context."""
        finding_json = finding.to_dict()
        
        context_text = ""
        if context:
            context_text = "\n\n".join(
                f"--- {snippet.topic} ---\n{snippet.content[:2000]}"
                for snippet in context
            )
        else:
            context_text = "(No relevant context retrieved)"
        
        return self.user_template.format(
            finding_json=__import__("json").dumps(finding_json, indent=2),
            context=context_text,
        )


# TriageResult JSON schema for the LLM to follow.
# NOTE: this is documentation/reference only — it is NOT passed to the Groq
# API. The client uses response_format={"type": "json_object"} (loose JSON
# mode), not json_schema/strict mode, since schema-enforced structured output
# support varies across Groq's hosted models. The fields below are instead
# manually described in prose in USER_TEMPLATE. If you change this schema,
# update USER_TEMPLATE to match — they are not linked programmatically.
TRIAGE_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {
            "type": "string",
            "description": "Plain-language explanation of the finding for a non-technical founder. 2-4 sentences. What is wrong, why it matters, what could happen. No jargon without definition."
        },
        "exploitability": {
            "type": "integer",
            "minimum": 1,
            "maximum": 5,
            "description": "Realistic exploitability given the actual evidence: 1=theoretical only, 2=requires significant skill/access, 3=moderate (public exploit exists), 4=high (automated tools exist), 5=trivial (script kiddie accessible). Must be grounded in the finding's evidence field, not hypothetical scenarios."
        },
        "fix": {
            "type": "string",
            "description": "Specific, actionable fix. Name the exact config change, code pattern, or dashboard setting. Not generic advice like 'improve security'. Example: 'In Supabase Dashboard > Authentication > Policies, enable RLS on users table and add policy: CREATE POLICY ... FOR SELECT USING (auth.uid() = id)'"
        },
        "revised_priority": {
            "type": "integer",
            "minimum": 1,
            "maximum": 5,
            "description": "Revised priority 1-5 combining severity and exploitability. 1=defer, 2=low, 3=medium, 4=high, 5=critical immediate action. Should reflect actual risk, not just scanner score."
        },
    },
    "required": ["explanation", "exploitability", "fix", "revised_priority"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a security educator explaining technical findings to a non-technical founder or product manager.

Your job: translate a scanner finding into a clear, honest assessment they can act on.

Rules:
1. Base your reasoning ONLY on the finding's evidence field (snippet, matched pattern, response status, headers). Do not invent attack scenarios beyond what the evidence shows.
2. Be specific, not scary. "An attacker could steal user emails" is better than "This could lead to a massive data breach."
3. The fix must be concrete: name a config setting, dashboard location, code pattern, or policy. No generic filler.
4. Exploitability must match the evidence. If the finding is a missing CSP header on a static marketing page, exploitability is low. If it's an exposed AWS key in a JS bundle, exploitability is high.
5. Output valid JSON matching the schema exactly. No extra fields, no markdown, no commentary."""

USER_TEMPLATE = """Finding (JSON):
{finding_json}

Relevant security knowledge:
{context}

Return a JSON object with exactly these fields:
- explanation (string): 2-4 sentences, plain language, non-technical audience
- exploitability (integer 1-5): grounded in the evidence above, not hypothetical
- fix (string): specific, actionable, names exact config/code/dashboard change
- revised_priority (integer 1-5): actual risk combining severity + exploitability

Output ONLY the JSON object. No markdown, no extra text."""

PROMPT_V1 = PromptTemplate(
    version="v1",
    system=SYSTEM_PROMPT,
    user_template=USER_TEMPLATE,
)