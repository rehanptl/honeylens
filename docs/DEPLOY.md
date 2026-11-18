# Deploying HoneyLens on Google Cloud

Time: about 45 minutes. Cost: covered by Google Cloud's free-trial credit for new accounts.

> **Rule #1:** this VM is bait. Put nothing else on it: no personal files, no other projects,
> no SSH keys that unlock other machines.

## 0. Before you start (on your laptop)

Make an SSH key if you don't have one (Mac/Linux Terminal, or Git Bash on Windows):

```bash
ssh-keygen -t ed25519          # press Enter for all prompts
cat ~/.ssh/id_ed25519.pub      # copy this whole line; you'll paste it into Google Cloud
```

## 1. Google Cloud account + budget alert

1. Go to console.cloud.google.com, sign in, and start the free trial.
2. Create a project called `honeylens`.
3. **Billing → Budgets & alerts → Create budget**: amount $5, alerts at 50/90/100%.
   This emails you if anything starts costing money.

## 2. Create the VM

**Compute Engine → VM instances → Create instance** (enable the Compute Engine API if asked):

| Setting | Value |
|---|---|
| Name | `honeylens` |
| Region | `us-central1` (any US region is fine) |
| Machine type | `e2-small` (2 GB RAM) |
| Boot disk | Change → **Ubuntu 24.04 LTS (x86/64)**, 20 GB |
| Networking → Network tags | `honeypot` |
| Security → Manage access → Add item (SSH keys) | paste the line from step 0 |

Click **Create**. Copy the **External IP** shown in the list.

> The external IP can change if you stop and start the VM. That's fine for this project.

## 3. Firewall rule

**VPC network → Firewall → Create firewall rule**:

| Setting | Value |
|---|---|
| Name | `honeypot-ports` |
| Targets | Specified target tags → `honeypot` |
| Source IPv4 ranges | `0.0.0.0/0` |
| Protocols and ports | TCP: `22,22022` |

## 4. Log in and move the real SSH off port 22

From your laptop. The username is the one at the end of your public key line (often your laptop username):

```bash
ssh YOUR_USERNAME@EXTERNAL_IP
```

Then on the VM:

```bash
# Ubuntu 24.04 uses socket activation for ssh; set the port in both places
sudo mkdir -p /etc/systemd/system/ssh.socket.d
printf '[Socket]\nListenStream=\nListenStream=22022\n' | sudo tee /etc/systemd/system/ssh.socket.d/port.conf
echo "Port 22022" | sudo tee /etc/ssh/sshd_config.d/port.conf
echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/nopass.conf
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket ssh
```

**Before closing this window**, open a NEW terminal on your laptop and check you can still get in:

```bash
ssh -p 22022 YOUR_USERNAME@EXTERNAL_IP
```

If that works, you're safe. If not, fix it from the old window.

> After this, the "SSH" button in the Google Cloud console won't work (it uses port 22,
> which is now the honeypot). Always use `ssh -p 22022 ...` from your laptop.

## 5. Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit
```

Log back in (`ssh -p 22022 ...`) so the Docker group takes effect.

## 6. Start HoneyLens

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/honeylens.git
cd honeylens
cp .env.example .env
nano .env     # paste GEMINI_API_KEY; set DJANGO_SECRET_KEY to any long random string
              # save: Ctrl+O, Enter, Ctrl+X
docker compose up -d --build
docker compose ps    # cowrie, mongo, worker, dashboard should all be running
```

Test the honeypot from your laptop. You'll get a fake login prompt; press Ctrl+C to leave:

```bash
ssh root@EXTERNAL_IP
```

Watch attacks arrive:

```bash
docker compose logs -f worker
```

## 7. View the dashboard (privately)

The dashboard only listens on the VM itself. From your laptop:

```bash
ssh -p 22022 -L 8000:localhost:8000 YOUR_USERNAME@EXTERNAL_IP
```

Leave that window open and visit http://localhost:8000.

## 8. When you're done (after 2–3 weeks)

1. Take screenshots of every dashboard page and write down the numbers.
2. Back up the data: `docker compose exec mongo mongodump --archive > backup.archive`
   then copy it to your laptop: `scp -P 22022 YOUR_USERNAME@EXTERNAL_IP:honeylens/backup.archive .`
3. **Delete the VM** in Compute Engine so it stops using credit.

## Housekeeping

| Task | Command |
|---|---|
| See what's running | `docker compose ps` |
| Follow pipeline logs | `docker compose logs -f worker` |
| Update after a `git pull` | `docker compose up -d --build` |
| Disk usage | `docker system df` |
| Stop everything | `docker compose down` (data is kept) |

Cowrie saves files attackers download (real malware) inside the `cowrie-var` volume under
`lib/cowrie/downloads`. Don't open or run them. Look up their SHA-256 on VirusTotal instead.

## Troubleshooting

- **`bind: address already in use` on port 22** – the real sshd is still on 22. Redo step 4.
- **Can't SSH on 22022** – check the firewall rule includes 22022 and the VM has the `honeypot` tag.
- **Dashboard empty** – `docker compose logs worker` prints how many events it ingested.
  None yet = no attackers yet, or port 22 is blocked by the firewall.
- **"analysis failed" in worker logs** – usually a bad API key or rate limit. It retries next
  cycle and gives up on a pattern after 3 failures.
