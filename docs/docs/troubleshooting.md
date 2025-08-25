# Troubleshooting

Help! I broke SeaBee! What should I do?

## Is SeaBee running?

- check with `systemctl status <daemon_name>` or with `ps -aux | grep seabee`

If so, we will need to shut it off. If SeaBee is running with the `--sigint allow` option,
then we can kill it with `sudo kill -2 <Pid>` or `systemctl stop <daemon_name>`.

## Is SeaBee turned off?

There may be something wrong with the internal state of SeaBee, if so, we can clean it up with `seabeectl clean`

- `sudo seabeectl clean --help`

To do a hard reset of SeaBee data, use `sudo seabeectl clean all`

This will remove all keys, policies, the root key, configurations, ect.

Once that is done, you should be able to use the [getting started](./getting_started.md) instructions to get SeaBee working again from scratch.

## If issues persist

please create an issue on our GitHub, we apologize this project is still under active development.
