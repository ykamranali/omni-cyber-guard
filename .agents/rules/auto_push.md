---
description: Always push code to GitHub and Docker automatically
---

# Auto-Push Updates

Whenever you make changes to the codebase and complete a task, you MUST automatically:

1. Stage all changes (`git add .`)
2. Commit the changes with a descriptive message (`git commit -m "..."`)
3. Push the changes to the GitHub repository (`git push`)
4. If the changes involve Docker configurations or if explicitly requested, run `docker-compose build` and `docker-compose push` or notify the user to configure a GitHub action.

Do not wait for the user to explicitly ask you to commit and push. Do it automatically at the end of every successful execution.
