Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1400
Set Height 750
Set Theme "Catppuccin Mocha"
Set Padding 10

# Launch TUI with pre-seeded data
Type "target/release/crack-coord run --with-agent --data-dir /tmp/crackswarm-demo/coord"
Enter
Sleep 6s

# Tasks tab (default) - show task list and detail
Sleep 2s

# Navigate down to see tasks
Type "j"
Sleep 1s
Type "j"
Sleep 2s

# Switch to Workers tab
Type "2"
Sleep 3s

# Switch to Results tab
Type "3"
Sleep 3s

# Switch to Audit Log tab
Type "4"
Sleep 3s

# Switch to Campaigns tab
Type "5"
Sleep 3s

# Back to Tasks tab
Type "1"
Sleep 2s

# Show help overlay
Type "?"
Sleep 4s

# Dismiss help
Type "?"
Sleep 2s

# Quit
Type "q"
Sleep 1s
