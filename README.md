# Libcommunist
Libcommunist is a simple library for peer to peer messaging in Linux and Windows operating systems.

## Building
To build libcommunist from source go to source code directory and execute following commands:

`meson -Dbuildtype=release build`\
`ninja -C build install`

You may need to set prefix by -Dprefix= option of meson (default prefix is /usr/local). Installation may need superuser privileges. Installation to custom directory can be done by following command:

`DESTDIR=/path/to/your/directory ninja -C build install`

## Dependencies
Libcommunist requires following libraries to be installed: [libtorrent-rasterbar](http://libtorrent.org/), [libzip](https://libzip.org/), [libgcrypt](https://www.gnupg.org/software/libgcrypt/index.html).

## Usage
See `Documentation.pdf` file of this repository for detailed description of library API.

## License

GPLv3 (see `COPYING`).

## Donation

If you want to help on developing this project, you can assist it by [donation](https://yoomoney.ru/to/4100117795409573) or by code development (contact author by email to obtain access to repositories)

## Contacts

You can contact author by email \
bobilev_yury@mail.ru