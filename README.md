### compliance
- `docker compose up --build`
- `localhost:5001`

---

#### aws deploy

1. Create an IAM user and attach the "AdministratorAccess" policy; then generate a CLI Access Key.


2. `add AWS Access Key ID, Access Key, and Region env vars to ~/.zshrc`;  my "BYO" IPv6 Pool was created in `us-west-1`

3. `npm i; cdk bootstrap; cdk deploy`