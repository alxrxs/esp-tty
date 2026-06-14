import os
Import("env")

managed = env.subst("$PROJECT_DIR/managed_components")
# On a clean checkout managed_components/ does not exist yet; guard the
# listdir so this PlatformIO pre-script doesn't abort the build with a
# FileNotFoundError before the directory has been populated.
if os.path.isdir(managed):
    for name in os.listdir(managed):
        if name == ".DS_Store":
            os.remove(os.path.join(managed, name))
