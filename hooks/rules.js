/**
 * Gitleaks Rules - Embedded secret detection patterns
 * 222 rules extracted from gitleaks config
 * https://github.com/gitleaks/gitleaks
 */

const RULES = [
  { id: '1password-secret-key', regex: /\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/, desc: '1Password Secret Key' },
  { id: '1password-service-account-token', regex: /ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}/, desc: '1Password Service Account Token' },
  { id: 'adafruit-api-key', regex: /(?:adafruit)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9_-]{32})/i, desc: 'Adafruit API Key' },
  { id: 'adobe-client-id', regex: /(?:adobe)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Adobe OAuth Client ID' },
  { id: 'adobe-client-secret', regex: /\b(p8e-(?i)[a-z0-9]{32})/i, desc: 'Adobe Client Secret' },
  { id: 'age-secret-key', regex: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/, desc: 'Age Secret Key' },
  { id: 'airtable-api-key', regex: /(?:airtable)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{17})/i, desc: 'Airtable API Key' },
  { id: 'airtable-personnal-access-token', regex: /\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b/, desc: 'Airtable Personal Access Token' },
  { id: 'algolia-api-key', regex: /(?:algolia)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Algolia API Key' },
  { id: 'alibaba-access-key-id', regex: /\b(LTAI(?i)[a-z0-9]{20})\b/, desc: 'Alibaba Cloud AccessKey ID' },
  { id: 'alibaba-secret-key', regex: /(?:alibaba)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{30})/i, desc: 'Alibaba Cloud Secret Key' },
  { id: 'anthropic-admin-api-key', regex: /\b(sk-ant-admin01-[a-zA-Z0-9_-]{93}AA)/, desc: 'Anthropic Admin API Key' },
  { id: 'anthropic-api-key', regex: /\b(sk-ant-api03-[a-zA-Z0-9_-]{93}AA)/, desc: 'Anthropic API Key' },
  { id: 'artifactory-api-key', regex: /\bAKCp[A-Za-z0-9]{69}\b/, desc: 'Artifactory API Key' },
  { id: 'artifactory-reference-token', regex: /\bcmVmd[A-Za-z0-9]{59}\b/, desc: 'Artifactory Reference Token' },
  { id: 'asana-client-id', regex: /(?:asana)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9]{16})/i, desc: 'Asana Client ID' },
  { id: 'asana-client-secret', regex: /(?:asana)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Asana Client Secret' },
  { id: 'atlassian-api-token', regex: /(?:atlassian|confluence|jira)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{20}[a-f0-9]{4})/i, desc: 'Atlassian API Token' },
  { id: 'atlassian-api-token-2', regex: /\b(ATATT3[A-Za-z0-9_\-=]{186})\b/, desc: 'Atlassian API Token' },
  { id: 'authress-service-client-access-key', regex: /\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+_/=-]{30,120})/, desc: 'Authress Service Client Access Key' },
  { id: 'aws-access-token', regex: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/, desc: 'AWS Access Key' },
  { id: 'aws-amazon-bedrock-api-key-long-lived', regex: /\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})/, desc: 'Amazon Bedrock Long-lived API Key' },
  { id: 'aws-amazon-bedrock-api-key-short-lived', regex: /bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t/, desc: 'Amazon Bedrock Short-lived API Key' },
  { id: 'azure-ad-client-secret', regex: /(?:^|[\s'"[:,(])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\s'"<),])/, desc: 'Azure AD Client Secret' },
  { id: 'beamer-api-token', regex: /(?:beamer)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(b_[a-z0-9=_\-]{44})/i, desc: 'Beamer API Token' },
  { id: 'bitbucket-client-id', regex: /(?:bitbucket)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Bitbucket Client ID' },
  { id: 'bitbucket-client-secret', regex: /(?:bitbucket)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{64})/i, desc: 'Bitbucket Client Secret' },
  { id: 'bittrex-access-key', regex: /(?:bittrex)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Bittrex Access Key' },
  { id: 'bittrex-secret-key', regex: /(?:bittrex)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Bittrex Secret Key' },
  { id: 'cisco-meraki-api-key', regex: /(?:meraki)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9a-f]{40})/i, desc: 'Cisco Meraki API Key' },
  { id: 'clickhouse-cloud-api-secret-key', regex: /\b(4b1d[A-Za-z0-9]{38})\b/, desc: 'ClickHouse Cloud API Secret Key' },
  { id: 'clojars-api-token', regex: /CLOJARS_[a-z0-9]{60}/i, desc: 'Clojars API Token' },
  { id: 'cloudflare-api-key', regex: /(?:cloudflare)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9_-]{40})/i, desc: 'Cloudflare API Key' },
  { id: 'cloudflare-global-api-key', regex: /(?:cloudflare)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{37})/i, desc: 'Cloudflare Global API Key' },
  { id: 'cloudflare-origin-ca-key', regex: /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b/, desc: 'Cloudflare Origin CA Key' },
  { id: 'codecov-access-token', regex: /(?:codecov)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Codecov Access Token' },
  { id: 'cohere-api-token', regex: /(?:cohere|CO_API_KEY)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-zA-Z0-9]{40})/i, desc: 'Cohere API Token' },
  { id: 'coinbase-access-token', regex: /(?:coinbase)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9_-]{64})/i, desc: 'Coinbase Access Token' },
  { id: 'confluent-access-token', regex: /(?:confluent)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{16})/i, desc: 'Confluent Access Token' },
  { id: 'confluent-secret-key', regex: /(?:confluent)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Confluent Secret Key' },
  { id: 'contentful-delivery-api-token', regex: /(?:contentful)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{43})/i, desc: 'Contentful Delivery API Token' },
  { id: 'curl-auth-header', regex: /\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?:Authorization:|Basic[ \t]|Bearer|(?:Api-)?Token| X-(?:[a-z]+-)?(?:Api-?)?(?:Key|Token))|'(?:Authorization:|Basic[ \t]|Bearer|(?:Api-)?Token| X-(?:[a-z]+-)?(?:Api-?)?(?:Key|Token))/i, desc: 'Curl Authorization Header' },
  { id: 'curl-auth-user', regex: /\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("[^"]+"|'[^']+'|[\w$@.-]+:[\w${}@.-]+)/i, desc: 'Curl User Auth' },
  { id: 'databricks-api-token', regex: /\b(dapi[a-f0-9]{32}(?:-\d)?)\b/, desc: 'Databricks API Token' },
  { id: 'datadog-access-token', regex: /(?:datadog)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{40})/i, desc: 'Datadog Access Token' },
  { id: 'defined-networking-api-token', regex: /(?:dnkey)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})/i, desc: 'Defined Networking API Token' },
  { id: 'digitalocean-access-token', regex: /\b(doo_v1_[a-f0-9]{64})\b/, desc: 'DigitalOcean Access Token' },
  { id: 'digitalocean-pat', regex: /\b(dop_v1_[a-f0-9]{64})\b/, desc: 'DigitalOcean Personal Access Token' },
  { id: 'digitalocean-refresh-token', regex: /\b(dor_v1_[a-f0-9]{64})\b/i, desc: 'DigitalOcean Refresh Token' },
  { id: 'discord-api-token', regex: /(?:discord)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{64})/i, desc: 'Discord API Key' },
  { id: 'discord-client-id', regex: /(?:discord)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9]{18})/i, desc: 'Discord Client ID' },
  { id: 'discord-client-secret', regex: /(?:discord)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{32})/i, desc: 'Discord Client Secret' },
  { id: 'doppler-api-token', regex: /dp\.pt\.(?i)[a-z0-9]{43}/, desc: 'Doppler API Token' },
  { id: 'droneci-access-token', regex: /(?:droneci)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'DroneCI Access Token' },
  { id: 'dropbox-api-token', regex: /(?:dropbox)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{15})/i, desc: 'Dropbox API Token' },
  { id: 'dropbox-long-lived-api-token', regex: /(?:dropbox)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43})/i, desc: 'Dropbox Long-lived API Token' },
  { id: 'dropbox-short-lived-api-token', regex: /(?:dropbox)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sl\.[a-z0-9\-=_]{135})/i, desc: 'Dropbox Short-lived API Token' },
  { id: 'duffel-api-token', regex: /duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}/, desc: 'Duffel API Token' },
  { id: 'dynatrace-api-token', regex: /dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}/, desc: 'Dynatrace API Token' },
  { id: 'easypost-api-token', regex: /\bEZAK(?i)[a-z0-9]{54}\b/, desc: 'EasyPost API Token' },
  { id: 'easypost-test-api-token', regex: /\bEZTK(?i)[a-z0-9]{54}\b/, desc: 'EasyPost Test API Token' },
  { id: 'etsy-access-token', regex: /(?:etsy)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{24})/i, desc: 'Etsy Access Token' },
  { id: 'facebook-access-token', regex: /\b(\d{15,16}[|%]?[0-9a-z\-_]{27,40})\b/i, desc: 'Facebook Access Token' },
  { id: 'facebook-page-access-token', regex: /\b(EAA[MC](?i)[a-z0-9]{100,})\b/, desc: 'Facebook Page Access Token' },
  { id: 'facebook-secret', regex: /(?:facebook)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Facebook Secret' },
  { id: 'fastly-api-token', regex: /(?:fastly)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{32})/i, desc: 'Fastly API Token' },
  { id: 'finicity-api-token', regex: /(?:finicity)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Finicity API Token' },
  { id: 'finicity-client-secret', regex: /(?:finicity)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{20})/i, desc: 'Finicity Client Secret' },
  { id: 'finnhub-access-token', regex: /(?:finnhub)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{20})/i, desc: 'Finnhub Access Token' },
  { id: 'flickr-access-token', regex: /(?:flickr)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Flickr Access Token' },
  { id: 'flutterwave-encryption-key', regex: /FLWSECK_TEST-(?i)[a-h0-9]{12}/, desc: 'Flutterwave Encryption Key' },
  { id: 'flutterwave-public-key', regex: /FLWPUBK_TEST-(?i)[a-h0-9]{32}-X/, desc: 'Flutterwave Public Key' },
  { id: 'flutterwave-secret-key', regex: /FLWSECK_TEST-(?i)[a-h0-9]{32}-X/, desc: 'Flutterwave Secret Key' },
  { id: 'flyio-access-token', regex: /\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))\b/, desc: 'Fly.io Access Token' },
  { id: 'frameio-api-token', regex: /fio-u-(?i)[a-z0-9\-_=]{64}/, desc: 'Frame.io API Token' },
  { id: 'freemius-secret-key', regex: /["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']/i, desc: 'Freemius Secret Key' },
  { id: 'freshbooks-access-token', regex: /(?:freshbooks)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Freshbooks Access Token' },
  { id: 'gcp-api-key', regex: /\b(AIza[\w-]{35})\b/, desc: 'GCP API Key' },
  { id: 'generic-api-key', regex: /(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})/i, desc: 'Generic API Key' },
  { id: 'github-app-token', regex: /(?:ghu|ghs)_[0-9a-zA-Z]{36}/, desc: 'GitHub App Token' },
  { id: 'github-fine-grained-pat', regex: /github_pat_\w{82}/, desc: 'GitHub Fine-grained PAT' },
  { id: 'github-oauth', regex: /gho_[0-9a-zA-Z]{36}/, desc: 'GitHub OAuth Token' },
  { id: 'github-pat', regex: /ghp_[0-9a-zA-Z]{36}/, desc: 'GitHub Personal Access Token' },
  { id: 'github-refresh-token', regex: /ghr_[0-9a-zA-Z]{36}/, desc: 'GitHub Refresh Token' },
  { id: 'gitlab-cicd-job-token', regex: /glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}/, desc: 'GitLab CI/CD Job Token' },
  { id: 'gitlab-deploy-token', regex: /gldt-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Deploy Token' },
  { id: 'gitlab-feature-flag-client-token', regex: /glffct-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Feature Flag Client Token' },
  { id: 'gitlab-feed-token', regex: /glft-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Feed Token' },
  { id: 'gitlab-incoming-mail-token', regex: /glimt-[0-9a-zA-Z_\-]{25}/, desc: 'GitLab Incoming Mail Token' },
  { id: 'gitlab-kubernetes-agent-token', regex: /glagent-[0-9a-zA-Z_\-]{50}/, desc: 'GitLab Kubernetes Agent Token' },
  { id: 'gitlab-oauth-app-secret', regex: /gl_oauth_[0-9a-zA-Z_\-]{64}/, desc: 'GitLab OAuth App Secret' },
  { id: 'gitlab-pat', regex: /glpat-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Personal Access Token' },
  { id: 'gitlab-pat-routable', regex: /glpatt_[0-9a-zA-Z_\-]{43}/, desc: 'GitLab Routable PAT' },
  { id: 'gitlab-ptt', regex: /glptt-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Pipeline Trigger Token' },
  { id: 'gitlab-rrt', regex: /glrrt-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab Runner Registration Token' },
  { id: 'gitlab-runner-authentication-token', regex: /glrauth-[0-9a-zA-Z_\-]{43}/, desc: 'GitLab Runner Auth Token' },
  { id: 'gitlab-runner-authentication-token-routable', regex: /glrarout-[0-9a-zA-Z_\-]{47}/, desc: 'GitLab Routable Runner Auth Token' },
  { id: 'gitlab-scim-token', regex: /gl_scim-[0-9a-zA-Z_\-]{20}/, desc: 'GitLab SCIM Token' },
  { id: 'gitlab-session-cookie', regex: /_gitlab_session=[0-9a-f]{40}/, desc: 'GitLab Session Cookie' },
  { id: 'gitter-access-token', regex: /gitter_[0-9a-zA-Z_\-]{40}/, desc: 'Gitter Access Token' },
  { id: 'gocardless-api-token', regex: /(?:gocardless)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{43})/i, desc: 'GoCardless API Token' },
  { id: 'grafana-api-key', regex: /(?:grafana)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{40})/i, desc: 'Grafana API Key' },
  { id: 'grafana-cloud-api-token', regex: /(?:grafana)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{50})/i, desc: 'Grafana Cloud API Token' },
  { id: 'grafana-service-account-token', regex: /(?:grafana)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(glsa_[a-z0-9]{40}_[0-9a-f]{8})/i, desc: 'Grafana Service Account Token' },
  { id: 'harness-api-key', regex: /(?:harness)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'Harness API Key' },
  { id: 'hashicorp-tf-api-token', regex: /(?:hashicorp|terraform)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'HashiCorp Terraform API Token' },
  { id: 'hashicorp-tf-password', regex: /(?:hashicorp|terraform)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:password|secret)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([\w.=-]{20,})/i, desc: 'HashiCorp Terraform Password' },
  { id: 'heroku-api-key', regex: /(?:heroku)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Heroku API Key' },
  { id: 'heroku-api-key-v2', regex: /\b[hH][eE][rR][oO][kK][uU][_\s]+[a-zA-Z0-9]{32}\b/, desc: 'Heroku API Key' },
  { id: 'hubspot-api-key', regex: /(?:hubspot)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{38})/i, desc: 'HubSpot API Token' },
  { id: 'huggingface-access-token', regex: /(?:huggingface)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(hf_[a-zA-Z0-9]{34})/i, desc: 'Hugging Face Access Token' },
  { id: 'huggingface-organization-api-token', regex: /(?:huggingface)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:org)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(hf_[a-zA-Z0-9]{34})/i, desc: 'Hugging Face Organization API Token' },
  { id: 'infracost-api-token', regex: /(?:infracost)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{20})/i, desc: 'Infracost API Token' },
  { id: 'intercom-api-key', regex: /(?:intercom)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{42})/i, desc: 'Intercom API Token' },
  { id: 'intra42-client-secret', regex: /(?:intra42)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Intra42 Client Secret' },
  { id: 'jfrog-api-key', regex: /(?:jfrog)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{73})/i, desc: 'JFrog API Key' },
  { id: 'jfrog-identity-token', regex: /(?:jfrog)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(BEARER[a-zA-Z0-9_@.-]{200,})/i, desc: 'JFrog Identity Token' },
  { id: 'jwt', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/, desc: 'JSON Web Token' },
  { id: 'jwt-base64', regex: /\beyJ[a-zA-Z0-9_+/]{20,}\.(?:eyJ[a-zA-Z0-9_+/]{20,}\.)?[a-zA-Z0-9_+/]{10,}\b/, desc: 'Base64-encoded JWT' },
  { id: 'kraken-access-token', regex: /(?:kraken)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Kraken Access Token' },
  { id: 'kubernetes-secret-yaml', regex: /apiVersion: v1\s+kind: Secret\s+type: Opaque\s+data:\s+[A-Za-z0-9+/=\s]+/i, desc: 'Kubernetes Secret YAML' },
  { id: 'kucoin-access-token', regex: /(?:kucoin)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{24})/i, desc: 'KuCoin Access Token' },
  { id: 'kucoin-secret-key', regex: /(?:kucoin)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret|key)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'KuCoin Secret Key' },
  { id: 'launchdarkly-access-token', regex: /(?:launchdarkly)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(api-[a-z0-9]{64})/i, desc: 'Launchdarkly Access Token' },
  { id: 'linear-api-key', regex: /(?:linear)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(lin_[a-z0-9]{43})/i, desc: 'Linear API Token' },
  { id: 'linear-client-secret', regex: /(?:linear)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Linear Client Secret' },
  { id: 'linkedin-client-id', regex: /(?:linkedin)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{14})/i, desc: 'LinkedIn Client ID' },
  { id: 'linkedin-client-secret', regex: /(?:linkedin)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{16})/i, desc: 'LinkedIn Client Secret' },
  { id: 'lob-api-key', regex: /(?:lob)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(live_[a-z0-9]{39})/i, desc: 'Lob API Key' },
  { id: 'lob-pub-api-key', regex: /(?:lob)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:pub)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(LIVE_[A-Z0-9]{39})/i, desc: 'Lob Publishable API Key' },
  { id: 'looker-client-id', regex: /(?:looker)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9a-f]{32})/i, desc: 'Looker Client ID' },
  { id: 'looker-client-secret', regex: /(?:looker)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9a-f]{32})/i, desc: 'Looker Client Secret' },
  { id: 'mailchimp-api-key', regex: /(?:mailchimp)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32}-(?:?:us[0-9]{1,2})?)/i, desc: 'Mailchimp API Key' },
  { id: 'mailgun-private-api-token', regex: /(?:mailgun)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(key-[0-9a-f]{32})/i, desc: 'Mailgun Private API Token' },
  { id: 'mailgun-pub-key', regex: /(?:mailgun)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:pub)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pubkey-[0-9a-f]{32})/i, desc: 'Mailgun Public Key' },
  { id: 'mailgun-signing-key', regex: /(?:mailgun)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:signing)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{140})/i, desc: 'Mailgun Signing Key' },
  { id: 'mapbox-api-token', regex: /(?:mapbox)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pk\.[a-z0-9=_\-]{51})/i, desc: 'Mapbox API Token' },
  { id: 'mattermost-access-token', regex: /(?:mattermost)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Mattermost Access Token' },
  { id: 'maxmind-license-key', regex: /(?:maxmind)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{16})/i, desc: 'MaxMind License Key' },
  { id: 'messagebird-api-token', regex: /(?:messagebird)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{47})/i, desc: 'MessageBird API Token' },
  { id: 'messagebird-client-id', regex: /(?:messagebird)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:client)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/i, desc: 'MessageBird Client ID' },
  { id: 'microsoft-teams-webhook', regex: /https?:\/\/[a-z0-9.]+\.webhook\.office\.com\/[a-z0-9/]+\/[a-zA-Z0-9=-]+/, desc: 'Microsoft Teams Webhook' },
  { id: 'netlify-access-token', regex: /(?:netlify)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(nf[a-z0-9]{59})/i, desc: 'Netlify Access Token' },
  { id: 'new-relic-browser-api-token', regex: /(?:newrelic|nr)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:browser)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'New Relic Browser API Token' },
  { id: 'new-relic-insert-key', regex: /(?:newrelic|nr)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:insert)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'New Relic Insert Key' },
  { id: 'new-relic-user-api-id', regex: /(?:newrelic|nr)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:user)((?:[\s\w.-]{0,20})id)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'New Relic User API ID' },
  { id: 'new-relic-user-api-key', regex: /(?:newrelic|nr)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:user)(?:[\s\w.-]{0,20})api(?:[\s\w.-]{0,20})key[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'New Relic User API Key' },
  { id: 'notion-api-token', regex: /(?:notion)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(secret_[a-zA-Z0-9]{48})/i, desc: 'Notion API Token' },
  { id: 'npm-access-token', regex: /(?:npm)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(npm_[a-z0-9]{36})/i, desc: 'npm Access Token' },
  { id: 'nuget-config-password', regex: /(?:nuget)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:password)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([\w.=-]{20,})/i, desc: 'NuGet Config Password' },
  { id: 'nytimes-access-token', regex: /(?:nytimes)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{32})/i, desc: 'NYTimes Access Token' },
  { id: 'octopus-deploy-api-key', regex: /(?:octopus)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(API-[A-Z0-9]{20})/i, desc: 'Octopus Deploy API Key' },
  { id: 'okta-access-token', regex: /(?:okta)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(00[a-z0-9]{40})/i, desc: 'Okta Access Token' },
  { id: 'openai-api-key', regex: /(?:openai)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sk-[a-zA-Z0-9]{48})/i, desc: 'OpenAI API Key' },
  { id: 'openshift-user-token', regex: /(?:openshift)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{86})/i, desc: 'OpenShift User Token' },
  { id: 'perplexity-api-key', regex: /(?:perplexity)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pplx-[a-z0-9]{51})/i, desc: 'Perplexity API Key' },
  { id: 'pkcs12-file', regex: /\b[a-zA-Z0-9/+=]{40,}={0,2}\b-----BEGIN\s+(?:CERTIFICATE|RSA\s+PRIVATE\s+KEY|DH\s+PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY|PRIVATE\s+KEY)-----\b/, desc: 'PKCS12 File' },
  { id: 'plaid-api-token', regex: /(?:plaid)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(access-(?:sandbox|development|production)-[a-f0-9]{48})/i, desc: 'Plaid API Token' },
  { id: 'plaid-client-id', regex: /(?:plaid)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:client)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{24})/i, desc: 'Plaid Client ID' },
  { id: 'plaid-secret-key', regex: /(?:plaid)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{30})/i, desc: 'Plaid Secret Key' },
  { id: 'planetscale-api-token', regex: /(?:planetscale|planetscale)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pscale_(?:token|oauth)_[a-z0-9=_\-]{50,})/i, desc: 'PlanetScale API Token' },
  { id: 'planetscale-oauth-token', regex: /(?:planetscale)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:oauth)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{80})/i, desc: 'PlanetScale OAuth Token' },
  { id: 'planetscale-password', regex: /(?:planetscale)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:password)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{60})/i, desc: 'PlanetScale Password' },
  { id: 'postman-api-token', regex: /(?:postman)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(PMAK[a-f0-9]{48})/i, desc: 'Postman API Token' },
  { id: 'prefect-api-token', regex: /(?:prefect)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pnu[a-z0-9]{48})/i, desc: 'Prefect API Token' },
  { id: 'private-key', regex: /-----BEGIN\s+(?:RSA\s+PRIVATE\s+KEY|DH\s+PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY| PRIVATE\s+KEY)-----/, desc: 'Private Key' },
  { id: 'privateai-api-token', regex: /(?:privateai)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sk-[a-z0-9=_\-]{48})/i, desc: 'PrivateAI API Token' },
  { id: 'pulumi-api-token', regex: /(?:pulumi)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pul-[a-f0-9]{48})/i, desc: 'Pulumi API Token' },
  { id: 'pypi-upload-token', regex: /(?:pypi)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(pypi-AgEIcBlb2[0-9a-zA-Z_-]{50})/i, desc: 'PyPI Upload Token' },
  { id: 'rapidapi-access-token', regex: /(?:rapidapi)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{38})/i, desc: 'RapidAPI Access Token' },
  { id: 'readme-api-token', regex: /(?:readme)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(rdme_[a-z0-9]{32})/i, desc: 'ReadMe API Token' },
  { id: 'rubygems-api-token', regex: /(?:rubygems)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(rubygems_[a-z0-9]{48})/i, desc: 'RubyGems API Token' },
  { id: 'scalingo-api-token', regex: /(?:scalingo)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(tk-[a-z0-9a-z]{48})/i, desc: 'Scalingo API Token' },
  { id: 'sendbird-access-id', regex: /(?:sendbird)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)((?:[\s\w.-]{0,20})id)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i, desc: 'Sendbird Access ID' },
  { id: 'sendbird-access-token', regex: /(?:sendbird)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})token[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{43})/i, desc: 'Sendbird Access Token' },
  { id: 'sendgrid-api-token', regex: /(?:sendgrid)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(SG\.[a-z0-9_-]{22}\.[a-z0-9_-]{43})/i, desc: 'SendGrid API Token' },
  { id: 'sendinblue-api-token', regex: /(?:sendinblue)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{20})/i, desc: 'Sendinblue API Token' },
  { id: 'sentry-access-token', regex: /(?:sentry)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sentry_[a-f0-9]{64})/i, desc: 'Sentry Access Token' },
  { id: 'sentry-org-token', regex: /(?:sentry)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:org)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sntrys_[a-z0-9=_\-]{60})/i, desc: 'Sentry Organization Token' },
  { id: 'sentry-user-token', regex: /(?:sentry)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:user)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{64})/i, desc: 'Sentry User Token' },
  { id: 'settlemint-application-access-token', regex: /(?:settlemint)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:app)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Settlemint Application Access Token' },
  { id: 'settlemint-personal-access-token', regex: /(?:settlemint)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:pat|personal)((?:[\s\w.-]{0,20})access)?[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Settlemint Personal Access Token' },
  { id: 'settlemint-service-access-token', regex: /(?:settlemint)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:service)((?:[\s\w.-]{0,20})access)?[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'Settlemint Service Access Token' },
  { id: 'shippo-api-token', regex: /(?:shippo)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(shippo_live_[a-z0-9=_\-]{44})/i, desc: 'Shippo API Token' },
  { id: 'shopify-access-token', regex: /(?:shopify)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Shopify Access Token' },
  { id: 'shopify-custom-access-token', regex: /(?:shopify)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:custom)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{48})/i, desc: 'Shopify Custom Access Token' },
  { id: 'shopify-private-app-access-token', regex: /(?:shopify)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:private)((?:[\s\w.-]{0,20})app)?(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{48})/i, desc: 'Shopify Private App Access Token' },
  { id: 'shopify-shared-secret', regex: /(?:shopify)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:shared)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{32})/i, desc: 'Shopify Shared Secret' },
  { id: 'sidekiq-secret', regex: /(?:sidekiq)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{64})/i, desc: 'Sidekiq Secret' },
  { id: 'sidekiq-sensitive-url', regex: /(?:sidekiq)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:sensitive)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:url)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(redis:[a-z0-9=_\-@:/\.]+)/i, desc: 'Sidekiq Sensitive URL' },
  { id: 'slack-app-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:app)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xapp-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack App Token' },
  { id: 'slack-bot-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:bot)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxb-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Bot Token' },
  { id: 'slack-config-access-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:config)((?:[\s\w.-]{0,20})access)?[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxa-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Configuration Access Token' },
  { id: 'slack-config-refresh-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:config)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:refresh)(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxr-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Configuration Refresh Token' },
  { id: 'slack-legacy-bot-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:legacy)(?:bot)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxb-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Legacy Bot Token' },
  { id: 'slack-legacy-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:legacy)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxe-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Legacy Token' },
  { id: 'slack-legacy-workspace-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:workspace)((?:[\s\w.-]{0,20})legacy)?[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxe-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack Legacy Workspace Token' },
  { id: 'slack-user-token', regex: /(?:slack)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:user)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(xoxp-[a-z0-9=_\-]{10,}[a-z0-9]{10,})/i, desc: 'Slack User Token' },
  { id: 'slack-webhook-url', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-z0-9]+/, desc: 'Slack Webhook URL' },
  { id: 'snyk-api-token', regex: /(?:snyk)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/i, desc: 'Snyk API Token' },
  { id: 'sonar-api-token', regex: /(?:sonar)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sqp_[a-z0-9]{40})/i, desc: 'Sonar API Token' },
  { id: 'sourcegraph-access-token', regex: /(?:sourcegraph)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sgp_[a-z0-9=_\-]{50})/i, desc: 'Sourcegraph Access Token' },
  { id: 'square-access-token', regex: /(?:square)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sq0atp-[a-z0-9=_\-]{22})/i, desc: 'Square Access Token' },
  { id: 'squarespace-access-token', regex: /(?:squarespace)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sq0atp-[a-z0-9=_\-]{22})/i, desc: 'Squarespace Access Token' },
  { id: 'stripe-access-token', regex: /(?:stripe)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(sk_live_[a-z0-9]{24})/i, desc: 'Stripe Access Token' },
  { id: 'sumologic-access-id', regex: /(?:sumologic)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:id)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{14})/i, desc: 'SumoLogic Access ID' },
  { id: 'sumologic-access-token', regex: /(?:sumologic)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9]{64})/i, desc: 'SumoLogic Access Token' },
  { id: 'telegram-bot-api-token', regex: /(?:telegram)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:bot)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9]{8,10}:[a-zA-Z0-9_-]{35})/i, desc: 'Telegram Bot API Token' },
  { id: 'travisci-access-token', regex: /(?:travis)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)((?:[\s\w.-]{0,20})token)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-zA-Z0-9]{22})/i, desc: 'Travis CI Access Token' },
  { id: 'twilio-api-key', regex: /(?:twilio)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:api)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:key)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(SK[a-f0-9]{32})/i, desc: 'Twilio API Key' },
  { id: 'twitch-api-token', regex: /(?:twitch)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*( twitch[a-z0-9]{30})/i, desc: 'Twitch API Token' },
  { id: 'twitter-access-secret', regex: /(?:twitter)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)((?:[\s\w.-]{0,20})secret)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-zA-Z0-9]{45})/i, desc: 'Twitter Access Secret' },
  { id: 'twitter-access-token', regex: /(?:twitter)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([0-9]{15,25}[a-zA-Z0-9_-]{40})/i, desc: 'Twitter Access Token' },
  { id: 'twitter-api-key', regex: /(?:twitter)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:api)((?:[\s\w.-]{0,20})key)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-zA-Z0-9]{25})/i, desc: 'Twitter API Key' },
  { id: 'twitter-api-secret', regex: /(?:twitter)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:api)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-zA-Z0-9]{50})/i, desc: 'Twitter API Secret' },
  { id: 'twitter-bearer-token', regex: /(?:twitter)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:bearer)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(A{20,}[a-zA-Z0-9_-]{50,})/i, desc: 'Twitter Bearer Token' },
  { id: 'typeform-api-token', regex: /(?:typeform)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(tfp_[a-z0-9=_\-]{49})/i, desc: 'Typeform API Token' },
  { id: 'vault-batch-token', regex: /(?:vault)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:batch)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(b_([a-z0-9]{20,}))/i, desc: 'Vault Batch Token' },
  { id: 'vault-service-token', regex: /(?:vault)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:service)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(s\.([a-z0-9]{20,}))/i, desc: 'Vault Service Token' },
  { id: 'yandex-access-token', regex: /(?:yandex)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(t1\.[a-z0-9=_\-]{60})/i, desc: 'Yandex Access Token' },
  { id: 'yandex-api-key', regex: /(?:yandex)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:api)((?:[\s\w.-]{0,20})key)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9_\-]{38})/i, desc: 'Yandex API Key' },
  { id: 'yandex-aws-access-token', regex: /(?:yandex)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:aws)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:access)(?:token)(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*(C茶叶[a-z0-9=_\-]{44})/i, desc: 'Yandex AWS Access Token' },
  { id: 'zendesk-secret-key', regex: /(?:zendesk)(?:[\s\w.-]{0,20})[\s'"]{0,3}(?:secret)((?:[\s\w.-]{0,20})key)?[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\s'"]*([a-z0-9=_\-]{42})/i, desc: 'Zendesk Secret Key' },
];

/**
 * Files/paths to skip scanning
 */
const SKIP_PATTERNS = [
  /\.(?:bmp|gif|jpe?g|png|svg|tiff?|woff2?|eot|otf)$/i,
  /\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|suo|dll|exe|pdb|gltf)$/i,
  /(?:^|\/)node_modules\//,
  /(?:^|\/)\.git\//,
  /\.lock$/,
  /gitleaks\.toml/i,
  /(?:^|\/)vendor\//,
];

/**
 * Line patterns to skip (allowlisted false positives)
 */
const SKIP_LINE_PATTERNS = [
  /^true|false|null$/i,
  /^[a-z]+$/i,
  /^\*+$/,
  /^\.+$/,
  /^\$?\{[\w ]+\}$/,
  /^%[A-Z_]+%$/,
  /^\{\{.*\}\}$/,
  /^@[\w]+@$/,
  /^\/Users\/[\w]+\/[\w.\/]+$/,
  /^\/(?:bin|etc|home|opt|tmp|usr|var)\//,
];

/**
 * Scan a single line for secrets
 */
function scanLine(line, filePath) {
  const findings = [];

  // Skip binary/skip files
  for (const pattern of SKIP_PATTERNS) {
    if (pattern.test(filePath)) {
      return findings;
    }
  }

  // Skip allowlisted lines
  for (const pattern of SKIP_LINE_PATTERNS) {
    if (pattern.test(line.trim())) {
      return findings;
    }
  }

  // Check against all rules
  for (const rule of RULES) {
    try {
      if (rule.regex.test(line)) {
        findings.push({
          ruleId: rule.id,
          description: rule.desc,
          match: line.substring(0, 100),
        });
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return findings;
}

/**
 * Scan a file for secrets
 */
function scanFile(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineFindings = scanLine(lines[i], filePath);
    for (const finding of lineFindings) {
      findings.push({
        ...finding,
        line: i + 1,
        file: filePath,
      });
    }
  }

  return findings;
}

module.exports = { RULES, SKIP_PATTERNS, scanLine, scanFile };