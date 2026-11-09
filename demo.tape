# Records docs/demo.gif and docs/demo.mp4 with VHS (https://github.com/charmbracelet/vhs).
#
#   make build && PATH="$PWD/bin:$PATH" vhs demo.tape
#
# Or run the "demo-gif" workflow, which records it on a clean runner.

Output docs/demo.gif
Output docs/demo.mp4

Require spotagentiq
Require jq

Set Shell bash
Set FontSize 15
Set Width 1200
Set Height 820
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# The "human": approves the email, rejects the delete. Off camera.
Hide
Type "(scripts/auto-approve.sh >/dev/null 2>&1 &) ; clear" Enter
Show

Type "spotagentiq demo" Sleep 600ms Enter
Sleep 13s

Type "spotagentiq verify --log /tmp/spotagentiq-demo-*/audit.jsonl" Sleep 600ms Enter
Sleep 5s
