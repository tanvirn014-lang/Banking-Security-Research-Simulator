package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"banksec-lab/internal/assistant"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/harness"
	"banksec-lab/internal/llm"
)

// runAssistant implements the `assistant` subcommand: it talks to the
// banking AI assistant in a disposable synthetic environment, and prints
// what the model said alongside what the gateway actually allowed.
//
// The two are printed separately and labelled, because they are
// different things. What the assistant says is a claim; what the gateway
// did is the record.
func runAssistant(env cliEnv, args []string) (string, error) {
	fs := flag.NewFlagSet("assistant", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	message := fs.String("message", "", "what the signed-in customer says to the assistant")
	document := fs.String("document", "", "optional third-party content the customer brings along (the indirect-injection vector)")
	as := fs.String("as", "alice", "which synthetic customer to sign in as")
	profileName := fs.String("profile", "hardened", "security profile to run the bank under")
	llmConfig := fs.String("llm-config", "", "path to the LLM settings file (default configs/llm.json next to the security profiles)")
	turns := fs.Int("turns", 4, "how many times the model may be consulted for one request")
	toolBudget := fs.Int("tool-budget", 0, "override the gateway's tool-call budget")
	payee := fs.String("payee", "", "add a synthetic customer as a saved transfer destination, e.g. mallory")
	expectAmount := fs.Int64("expect-amount", 0, "only approve a drafted transfer whose amount matches this, in minor units; 0 disables the check")
	approve := fs.Bool("approve-transfer", false, "grant the customer approval for the first transfer the assistant drafts (the happy path; off by default)")
	list := fs.Bool("list", false, "list the tool catalog and security boundary, and talk to no model")
	showPrompt := fs.Bool("show-prompt", false, "print the assistant's system prompt and exit")

	if err := fs.Parse(args); err != nil {
		return "", fmt.Errorf("parse flags for assistant: %w", err)
	}
	if fs.NArg() > 0 {
		return "", fmt.Errorf("assistant takes no positional arguments, got %q", fs.Arg(0))
	}

	if *list {
		return listAssistantSurface(), nil
	}
	if *showPrompt {
		return assistant.SystemPrompt() + "\n", nil
	}
	if strings.TrimSpace(*message) == "" {
		return "", fmt.Errorf("--message is required (or use --list to see the tool catalog)")
	}

	settings, err := loadLLMSettings(env, *llmConfig)
	if err != nil {
		return "", err
	}

	profile, err := loadNamedProfile(env, *profileName)
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	provider, err := buildProvider(ctx, settings.Assistant, llm.CapabilityTools)
	if err != nil {
		return "", err
	}

	bankEnv, err := harness.NewLocalEnvironment(profile)
	if err != nil {
		return "", fmt.Errorf("wire a synthetic bank: %w", err)
	}
	defer bankEnv.Close()

	seeded, err := assistant.SeedSyntheticAccounts(ctx, bankEnv.Client, assistant.SyntheticFixture())
	if err != nil {
		return "", fmt.Errorf("seed synthetic accounts: %w", err)
	}
	acct, ok := seeded.Accounts[*as]
	if !ok {
		return "", fmt.Errorf("--as %q is not a synthetic customer (available: %s)",
			*as, strings.Join(seeded.Owners(), ", "))
	}

	limits := assistant.DefaultLimits()
	if *toolBudget > 0 {
		limits.MaxToolCalls = *toolBudget
	}
	gateway, err := assistant.NewGateway(bankEnv.Client, limits)
	if err != nil {
		return "", err
	}
	bot, err := assistant.NewAssistant(provider, gateway, *turns)
	if err != nil {
		return "", err
	}

	session := assistant.Session{
		ID:        "cli-session",
		Principal: domain.Principal{ID: domain.PrincipalID(*as), Role: domain.RoleAccountOwner},
		Accounts:  []domain.AccountID{acct},
	}
	if *payee != "" {
		payeeAcct, ok := seeded.Accounts[*payee]
		if !ok {
			return "", fmt.Errorf("--payee %q is not a synthetic customer (available: %s)",
				*payee, strings.Join(seeded.Owners(), ", "))
		}
		session.Payees = append(session.Payees, assistant.Payee{Name: *payee, Account: payeeAcct})
	}

	var report strings.Builder
	if profile.Name != "hardened" {
		fmt.Fprintf(&report, "WARNING: the bank is running under the %q profile, which deliberately disables controls.\n\n", profile.Name)
	}
	fmt.Fprintf(&report, "model=%s provider=%s profile=%s signed in as=%s (%s)\n",
		provider.Model(), provider.Name(), profile.Name, *as, acct)
	fmt.Fprintf(&report, "synthetic accounts: ")
	for i, owner := range seeded.Owners() {
		if i > 0 {
			report.WriteString(", ")
		}
		fmt.Fprintf(&report, "%s=%s", owner, seeded.Accounts[owner])
	}
	report.WriteString("\n\n")

	transcript, err := bot.Handle(ctx, session, assistant.Input{
		UserMessage:      *message,
		UntrustedContent: *document,
	})
	if err != nil {
		return "", err
	}

	// The optional happy path: approve a drafted transfer the way a real
	// customer would, on a separate channel, then let the assistant
	// finish.
	//
	// What is being approved is printed BEFORE the approval, from the
	// gateway's own record. The whole value of this control is that a
	// human sees the transfer; approving whatever the assistant drafted
	// first, sight unseen, reduces it to a rubber stamp and would wave
	// through an injected draft as readily as a legitimate one
	// (assessment finding F-06).
	if *approve {
		if id := firstConfirmationID(transcript); id != "" {
			from, to, amount, found := gateway.PendingTransfer(id)
			if !found {
				fmt.Fprintf(&report, "cannot approve %s: no such pending transfer\n\n", id)
				report.WriteString(renderTranscript(transcript, gateway))
				return report.String(), nil
			}

			report.WriteString("PENDING TRANSFER AWAITING APPROVAL\n")
			fmt.Fprintf(&report, "  confirmation: %s\n", id)
			fmt.Fprintf(&report, "  debit:        %s\n", from)
			fmt.Fprintf(&report, "  credit:       %s\n", to)
			fmt.Fprintf(&report, "  amount:       %d (minor units)\n", amount)

			if *expectAmount > 0 && int64(amount) != *expectAmount {
				fmt.Fprintf(&report, "  NOT APPROVED: the drafted amount differs from the --expect-amount of %d.\n", *expectAmount)
				report.WriteString("  An altered or injected draft looks exactly like this.\n\n")
				report.WriteString(renderTranscript(transcript, gateway))
				return report.String(), nil
			}
			report.WriteString("  approving, because --approve-transfer was passed\n\n")

			if err := gateway.ApproveTransfer(session.ID, id); err != nil {
				fmt.Fprintf(&report, "approval failed: %v\n\n", err)
			} else {
				fmt.Fprintf(&report, "customer approved transfer %s out of band\n\n", id)
				follow, ferr := bot.Handle(ctx, session, assistant.Input{
					UserMessage: fmt.Sprintf("I have approved it. Confirmation id %s. Please complete the transfer.", id),
				})
				if ferr == nil {
					transcript.Turns = append(transcript.Turns, follow.Turns...)
					transcript.FinalAnswer = follow.FinalAnswer
				}
			}
		} else {
			report.WriteString("nothing to approve: the assistant drafted no transfer\n\n")
		}
	}

	report.WriteString(renderTranscript(transcript, gateway))
	return report.String(), nil
}

// renderTranscript prints the exchange with the model's words and the
// gateway's decisions clearly separated.
func renderTranscript(t assistant.Transcript, gw *assistant.Gateway) string {
	var b strings.Builder

	for _, turn := range t.Turns {
		fmt.Fprintf(&b, "--- turn %d ---\n", turn.Index+1)
		if turn.Reply != "" {
			fmt.Fprintf(&b, "assistant says: %s\n", strings.TrimSpace(turn.Reply))
		}
		for _, inv := range turn.Invocations {
			status := "REFUSED"
			if inv.Executed {
				status = "EXECUTED"
			}
			fmt.Fprintf(&b, "  tool %s(%s) -> %s [%s]\n",
				inv.Proposed.Name, renderArgs(inv.Proposed.Arguments), status, inv.Decision)
			if inv.Reason != "" {
				fmt.Fprintf(&b, "    reason: %s\n", inv.Reason)
			}
			if inv.Executed && len(inv.Result) > 0 {
				fmt.Fprintf(&b, "    result: %s\n", renderResult(inv.Result))
			}
			fmt.Fprintf(&b, "    acted as: %s (from the session, not from the model)\n", inv.EffectiveActor)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "stop reason: %s\n", t.StopReason)
	if t.Error != "" {
		fmt.Fprintf(&b, "error: %s\n", t.Error)
	}
	fmt.Fprintf(&b, "tool calls proposed: %d   executed: %d\n", gw.AttemptedCount(), gw.ExecutedCount())
	return b.String()
}

func renderArgs(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, args[k]))
	}
	return strings.Join(parts, " ")
}

func renderResult(result map[string]string) string {
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, result[k]))
	}
	return strings.Join(parts, " ")
}

// firstConfirmationID finds the confirmation id of the first transfer
// the assistant drafted, if any.
func firstConfirmationID(t assistant.Transcript) string {
	for _, inv := range t.ExecutedInvocations() {
		if id := inv.Result["confirmation_id"]; id != "" {
			return id
		}
	}
	return ""
}

// loadLLMSettings resolves the LLM settings file, defaulting to
// llm.json alongside the security profiles.
func loadLLMSettings(env cliEnv, override string) (llm.Settings, error) {
	path := override
	if path == "" {
		path = filepath.Join(filepath.Dir(env.ProfilePath), "llm.json")
	}
	settings, err := llm.LoadSettings(path)
	if err != nil {
		return llm.Settings{}, err
	}
	return settings, nil
}

// buildProvider constructs a verified provider from one role's
// configuration. The mock provider is available for a dry run that
// needs no model server, and says plainly that it is not a model.
func buildProvider(ctx context.Context, cfg llm.Config, required ...llm.Capability) (llm.Provider, error) {
	switch cfg.Provider {
	case llm.ProviderMock:
		return llm.NewMockProvider(cfg.Model,
			llm.MockTurn{Content: "[mock provider: no model was consulted]"}), nil
	case llm.ProviderOllama:
		return llm.NewOllamaProvider(ctx, cfg, required...)
	default:
		return nil, fmt.Errorf("llm provider %q is not implemented", cfg.Provider)
	}
}

// listAssistantSurface prints the tool catalog and the security
// boundary, consulting no model.
func listAssistantSurface() string {
	var b strings.Builder

	b.WriteString("tools available to the assistant:\n")
	for _, spec := range assistant.ToolCatalog() {
		fmt.Fprintf(&b, "  %-26s %s\n", spec.Name, spec.Description)
		if required, ok := spec.Parameters["required"].([]string); ok && len(required) > 0 {
			fmt.Fprintf(&b, "  %-26s required: %s\n", "", strings.Join(required, ", "))
		}
	}

	b.WriteString("\nthe assistant cannot:\n")
	for _, line := range []string{
		"change which customer it is acting as (the principal is re-derived from the session on every call)",
		"grant itself a permission or a role",
		"read or act on an account the signed-in customer does not own",
		"execute a transfer directly -- there is no such tool",
		"approve its own drafted transfer (approval is granted on a path no tool reaches)",
		"reuse a confirmation (one approval authorizes exactly one transfer)",
		"read cryptographic key material",
		"run SQL, shell commands, or arbitrary code",
		"reach the network or the filesystem",
		"exceed its tool-call budget",
	} {
		fmt.Fprintf(&b, "  - %s\n", line)
	}

	b.WriteString("\nhow those are enforced:\n")
	b.WriteString("  Not by the system prompt. Every item above is checked by the tool gateway\n")
	b.WriteString("  (internal/assistant) and by the bank's own authorization layer, which the\n")
	b.WriteString("  gateway reaches through the same client the CLI and attack harness use.\n")
	b.WriteString("  The prompt states the same limits so the model behaves sensibly, but nothing\n")
	b.WriteString("  depends on it being obeyed.\n")

	b.WriteString("\nsynthetic fixture:\n")
	for _, acct := range assistant.SyntheticFixture().Accounts {
		fmt.Fprintf(&b, "  %-10s opening balance %d (minor units)\n", acct.Owner, acct.OpeningBalance)
	}

	return b.String()
}
