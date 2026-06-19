# vhs tape — skillprov happy path: manifest -> sign -> verify (PASS) -> verify poisoned (REJECTED).
# Render in CI via .github/workflows/demo.yml, or locally:
#   go build -o /usr/local/bin/skillprov .   # (or put ./skillprov on PATH)
#   vhs docs/demo.tape                        # writes assets/demo.gif
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 700
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 45ms

Type "# 1) Emit a capability manifest + SBOM for an honest skill"
Enter
Sleep 600ms
Type "skillprov manifest ./testdata/clean-skill"
Enter
Sleep 2s

Type "# 2) Sign the canonical manifest with a local ed25519 key"
Enter
Sleep 600ms
Type "skillprov sign ./testdata/clean-skill --key dev.key"
Enter
Sleep 2s

Type "# 3) Verify it — green PASS: signature valid, observed capabilities declared"
Enter
Sleep 600ms
Type "skillprov verify ./testdata/clean-skill"
Enter
Sleep 2.5s

Type "# 4) Now verify a poisoned skill — undeclared net + fs-write -> REJECTED"
Enter
Sleep 600ms
Type "skillprov manifest ./testdata/poisoned-skill && skillprov sign ./testdata/poisoned-skill --key dev.key"
Enter
Sleep 2s
Type "skillprov verify ./testdata/poisoned-skill"
Enter
Sleep 3.5s
