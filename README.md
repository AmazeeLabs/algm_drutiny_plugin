# ALGM Drutiny Plugin

This plugin provides a list of standard policy collections that can be used by Drutiny.


## Setup

  1. `git clone git@github.com:AmazeeLabs/algm_drutiny.git`

  2. `composer install -o`

  3. Need Drush - https://docs.drush.org/en/9.x/install/

    We also need Drush locally (preferably Drush 9+). There are also a couple of things you need to ensure your drush alias files have in order to get this working with Drutiny which we will cover below.

    If you have drush but need to update to Drush 9 way of things, then this is your friend:
    https://stackoverflow.com/questions/55587919/where-drush-9-aliases-file-should-be-located-in-drupal-8

    To install globally in terminal (But aware that this will affect previous Drush setup)
    In your user folder.

    $ `composer global require drush/drush:^9`

  4. Drush Setup folder structure in ~/.drush/

    ~/.drush/
      - cache/ (might not be there)
      - commands/ (might not be there)
      - sites/ ( Add this Drush Alias folder. This is where you add your sitename.site.yml for each sites you'll connect to.)
      - drush.yml

      - drush.yml should have:

      drush:
        paths:
          alias-path:
            - '${env.home}/.drush/sites'


  5. Test Drutiny is running - `./vendor/bin/drutiny`

## What is this?

This repo is a plugin for Drutiny - meaning that it gets added ontop of core Drutiny as an extension which we then build, release and run as a single binary phar file. This plugin therefore provides us a way to add in our own policies, profiles, formatters and anything else we like in order to extend the existing Drutiny functionality.

The Docs are great for explaining this - https://drutiny.readthedocs.io/en/2.x/README/

- Policies - https://drutiny.readthedocs.io/en/2.x/policy/
- Profiles - https://drutiny.readthedocs.io/en/2.x/profiles/


## The workflow

To add policies/profiles or extend our Drutiny plugin in any way we need to do a few things:

  1. Ensure we have the latest locally (fetch and pull to be sure)
  2. Add what we need to, commit and push up to PR or master (depending on if testing is needed)
  3. Testing can be done via the `drupal-web` docker instance in this repo, or by using remote drush aliases and running them against these sites directly. Of course, be wary of running things against production sites if you are unsure of the expected results.
  4. Once pushed to master, and are happy things are tested/working properly then we need to create a new tag.
  5. Fetch all tags from remote, and check the list, add a new tag with `git tag v1.0.x` for example - add a note  if you like with the `-a` flag. Then push up to our origin with `git push origin --tags`.
  6. This will trigger the phar builder github action we have. You can see this build here - https://github.com/AmazeeLabs/algm_drutiny/actions
  7. A new release will be built - check the output of the build to see if your policies are there. You could also download the phar locally and run it against a site locally to check if its working as expected.
  8. Then we will use the new latest release in our ansible/awx playbooks!


## Using Drutiny

There are two core commands in Drutiny which we run: policy:audit and profile:run.

### policy:audit

This runs the policy against a target (mostly likely a drush target) which will do the checks we want to run.

Fundamentally, we need to provide a policy (e.g. `algm:ModuleUpdates`) and a target (e.g. drush alias `@site-prod.site-name`). We can also pass in options such as `--format` which defines the output format. Parameters / default values can also be passed into policies with the `-p` flag, for example `-p module=8.6.8`.

`policy:audit [options] [--] <policy> <target>`

The final command would look something like this:
`./vendor/bin/drutiny policy:audit algm:ModuleUpdates @site-prod.site-name --format=markdown`

### profile:run

This runs the profile against a target which will go through and check the entire policy suite.

For profiles, we need to provide a profile name (e.g. `algm_sla_site`) and a target (e.g. drush alias `@site-prod.site-name`). We can also pass in options such as '--format' which defines the output format.

`  profile:run [options] [--] <profile> <target>`

The final command would look something like this:
`./vendor/bin/drutiny profile:run algm_sla_site @site-prod.site-name --format==markdown`


## Adding a new policy

To add a new policy we need two files: a new policy yaml added here (https://github.com/AmazeeLabs/algm_drutiny/tree/master/Policies) and also a new Audit class here (https://github.com/AmazeeLabs/algm_drutiny/tree/master/src/Audit)

### Policy details

Most importantly, we have the `$sandbox` object which is the runtime object that will execute our policies.

#### exec
`exec` is the method that will access the remote shell and fire a given command - e.g. `$output = $sandbox->exec('ls -la');`

#### drush
Drush can be run with the `drush` method. Drutiny supports camel case naming here - e.g. `$list = $sandbox->drush(['format' => 'json'])->pmList();`
If json format is given, drutiny will parse the response and return the output in PHP.


## Drush alias

An example Drush 9 alias file:

```
prod:
  host: ssh.lagoon.amazeeio.cloud
  root: /app/web
  user: site-prod
  remote-host: ssh.lagoon.amazeeio.cloud
  remote-user: site-prod
  ssh-options: '-o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 32222'
```

Please note, this is an example only and you should update your drush aliases with these values just to have it working with Drutiny, rather than replace it entirely.

There is also an `example.drush.alias.yml` in this repo.

Don't forget to clear drush caches when making a change/adding a new site alias - `drush cc`

For more config options - this is useful https://github.com/drush-ops/drush/blob/master/examples/example.site.yml


## Useful things

Checking policy list available to us:
    `./vendor/bin/drutiny policy:list`

Checking profiles list:
    `./vendor/bin/drutiny profile:list`

You might need to clear Drutiny cache:
    `./vendor/bin/drutiny cache:clear`


## Development and testing

Inside the package there is a Drupal installation where you can test
your policies against. Please follow the
[drupal-web/README.md](drupal-web/README.md) file
