# Usage: run from inside the .demo/ directory so the tape's relative paths
# (PATH lookup for the supplyscan binary, `ls`, `cat package.json`) resolve.
#
#   cd .demo
#   vhs demo.tape
#
# Outputs demo.gif and demo.mp4 next to this tape. mp4 requires ffmpeg
# (`brew install ffmpeg`).

Output demo.gif
Output demo.mp4

Set Shell "zsh"
Set FontFamily "JetBrainsMono Nerd Font Mono"
Set FontSize 13
Set Width 1280
Set Height 760
Set Theme { "name": "Monokai", "background": "#272822", "foreground": "#f8f8f2", "cursor": "#f8f8f0", "selection": "#49483e", "black": "#272822", "red": "#f92672", "green": "#a6e22e", "yellow": "#f4bf75", "blue": "#66d9ef", "magenta": "#ae81ff", "cyan": "#a1efe4", "white": "#f8f8f2", "brightBlack": "#75715e", "brightRed": "#f92672", "brightGreen": "#a6e22e", "brightYellow": "#f4bf75", "brightBlue": "#66d9ef", "brightMagenta": "#ae81ff", "brightCyan": "#a1efe4", "brightWhite": "#f9f8f5" }
Set TypingSpeed 70ms
Set PlaybackSpeed 1.0

# Hidden setup: put the project binary on PATH and start with a clean prompt.
Hide
Type "export PATH=`pwd`/..:$PATH && export PS1='%F{green}acme-dashboard%f %F{blue}$%f ' && clear"
Enter
Show

Sleep 1s

# Show the project layout.
Type "ls"
Enter
Sleep 1500ms

Type "cat package.json"
Enter
Sleep 3s

# Confirm the IOC database is loaded and ready.
Type "supplyscan status"
Enter
Sleep 4s

# Run the full scan — supply-chain compromises + npm audit vulnerabilities.
Type "supplyscan scan ."
Enter
Sleep 8s

# Drill into a single compromised package.
Type "supplyscan check @ctrl/deluge 7.2.2"
Enter
Sleep 5s
