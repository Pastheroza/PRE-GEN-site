# Get your ToG with an AI agent

Give this to any AI agent that works for you: paste the line below, or give it the address of this file.

> Read https://www.pregen.org/tog/agent.md and help me get my ToG code. Ask me the questions it lists. Do only what it says you may do.

A ToG code is the number that names you (or your company) in a registry. It records your answer to one question: may AI generate me? The licence is ToG-L 1.0 (https://www.pregen.org/tog/1.0). Everything here is free.

## What you, the agent, may do and may not do

You may ask the person questions, explain the choices, open the registry's page for them, place a proof line on a website or profile they own and have told you to edit, and check a code's public status.

You may not create an account, accept terms or consent for the person, enter a password, an authenticator code or a verification code, claim a code is confirmed before the check says so, or invent a code. A code is issued only by a registry, and the person's own press and second factor are part of it. These steps are the person's, and the registry asks for them.

## Step 1. Ask four things

1. Is the ToG for the person themselves, for a company's brand, products or characters, or for a child (then a parent or legal guardian does it)?
2. Is the person 18 or older? If they are 13 to 17, stop: a parent or guardian must register for them at the registry. Do not build a link with their answers.
3. What is the answer? **No** (AI may not generate me), **Yes, only what I approve**, or **Yes, within my rules**. **Yes, only what I approve** is recorded, but no registry carries it out yet: PRAMPTA answers every request under it as a No (`deny`, `PG_TERMS_EXCLUDED`).
4. Which registry? Today: PRAMPTA (https://prampta.com). The list is at https://www.pregen.org/tog/create.

## Step 2. Open the registry

- **A person who says No.** Open this link for them. It carries the answer, and nothing else, in the part after `#`, which is never sent to a server:

  `https://prampta.com/start?path=tog#tog=v1.eyJhZ2UiOiIxOCsiLCJkZWNpc2lvbiI6Im5vIn0`

  The registry asks for the person's name and email, makes them sign in or create an account, and issues the code.
- **Any other answer** (a yes, a company, a parent): open `https://prampta.com/start?path=tog` and tell the person the screens are short: who, answer, what and where, check, account. They choose; you do not.

Never put a name, a date of birth, an email or a domain in a link.

## Step 3. The person gets a pending code

The registry shows a code like `TOG-PRAM-900000037K`. It is **pending**: it permits and forbids nothing until it is confirmed, and it expires after 7 days if it is not.

## Step 4. Confirm it

- **A person:** put the line below, alone on its own line, on a public page or profile they control (their website, a public account). If they asked you to edit their site, do it. Otherwise tell them where it goes.

  `ToG: TOG-PRAM-900000037K`

  The registry's page has a button to check it.
- **A company:** serve `https://<its domain>/.well-known/tog.json` in the form the registry gives on its return page (`record` and `claim` come from the registry; never invent them):

  `{"tog": 1, "registered": [{"notary": "<prefix>", "record": "<record page>", "claim": "<claim>"}]}`

## Step 5. Check it

`https://www.pregen.org/lookup?code=<the code>` shows the status in plain words. `active` means confirmed. An email address alone never confirms a code.

## What to tell the person, in short

- A **pending** code does nothing yet. A confirmed **No** applies to every registry and AI service that uses ToG.
- A **Yes, within my rules** opens only what they allowed, and they can change or withdraw it. **Yes, only what I approve** is recorded, but for now registries answer it as a No. A No always wins over a Yes.
- Nothing is sold and nothing is charged for a code.
