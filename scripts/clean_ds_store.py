import os
Import("env")

managed = env.subst("$PROJECT_DIR/managed_components")
for name in os.listdir(managed):
    if name == ".DS_Store":
        os.remove(os.path.join(managed, name))
