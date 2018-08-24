
# Send Quip notification messages to OSX notification center

[Quip](https://quip.com) does not notify me about any notifications I receive, so I
missed important messages pretty often. This little app was created to fix that.

## What it does

It sends Quip notifications to OSX notification center.

### Features

 * Notifies about direct messages, mentions, and all messages in threads (channels)
   that are configured as "important".
 * Delivers all missed messages once the program re-connects, so no messages are missed
   if laptop was closed, offline, etc.
 * Will re-connect automatically if disconnected.
 * Configurable sound effect.

### Caveats

 * Quip format parsing is pretty rudimentary.
 * Requires some knowledge to install and use it (it's a Ruby app).
 * This app is good enough for me but no more: **this is a quick one-evening project because
   Quip was giving me rage fits, it's nowhere near production quality.**

### TODOs

 * The app should notify if/when it crashes, looses connection to Quip for a long time, etc.
 * Find out about token validity. It might expire on me here, and I have no way of knowing when.

## How to install and use it

 * Clone the repo
 * Install dependencies: `gem install bundler ; bundle`
 * Configure it: Copy `config/application.yml-sample` to `config\application.yml` and
   edit it to your liking. Only access token is required, other settings are optional,
   *but `api_base_url` is essential if using on-premises Quip!*
 * Run `quip_notifier.rb -d`, it should daemonize itself when run with "-d" parameter.
 * Check `logs/quip_notifier.log` for more info.
 * Configuring this app for running upon user login is left as an exercise to the reader.
