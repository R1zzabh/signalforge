# Lab attacker boundary

The controller is the only attacker entry point. It exposes a fixed allowlist
of safe scenarios and always targets `sf-target` on the isolated Compose network.
There is no arbitrary command or target input.
