# vhs tape for the skillsig demo.
# Render with:  vhs assets/demo.tape   (produces assets/demo.gif)
# Prereqs:      go build -o skillsig .  &&  cp -r testdata/clean-skill testdata/poisoned-skill .
#
# This mirrors the recorded assets/demo.cast: emit a manifest, sign it, verify
# the honest skill (green PASS), then verify the poisoned skill (red REJECTED).

Output assets/demo.gif

Set Theme "Dracula"
Set FontSize 18
Set Width 1100
Set Height 640
Set Padding 24
Set TypingSpeed 45ms

Type "skillsig manifest ./clean-skill"
Enter
Sleep 1500ms

Type "skillsig sign ./clean-skill --key dev.key"
Enter
Sleep 1500ms

Type "skillsig verify ./clean-skill"
Enter
Sleep 2s

Type "skillsig verify ./poisoned-skill   # the supply-chain catch"
Enter
Sleep 3s
