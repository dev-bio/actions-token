# Actions Token

Action to generate and optionally scope down application tokens for use in workflows.

**Example:**
```yaml
- name: Generate Token
  uses: dev-bio/actions-token@v1.0.0
  id: token
  with:
    app-id: ${{ secrets.APP_ID }}
    app-pk: ${{ secrets.APP_PK }}
    duration: 5 # optional duration in minutes, this is the default
    permissions: | # optional settings for scoping down the token
      repositories: [ 'dev-bio/actions-token' ]
      scopes:
        contents: write
        metadata: read


- name: Privileged Action
  uses: something/something@v0.0.0
  with:
    token: ${{ steps.token.outputs.token }}
```