# Archived

This repo has been moved into [MCProtocolLib](https://github.com/rfresh2/MCProtocolLib) and will no longer receive updates here

# MCAuthLib
MCAuthLib is a library for authentication with Minecraft accounts. It is used in projects such as MCProtocolLib to handle authenticating users.

This code is forked from [GeyserMC/MCAuthLib](https://github.com/GeyserMC/MCAuthLib) and [tycrek/MCAuthLib](https://github.com/tycrek/MCAuthLib)

# Features

* Simple Microsoft Account authentication using [OpenAuth](https://github.com/Litarvan/OpenAuth).
  * MCAuthLib does not provide interfaces for 2FA or OAuth workflows. This is based on requirements for unattended login ability with bots.
  * This library is intended to be used as a bridge between OpenAuth and the MCProtocolLib libraries.
* JDK17

## Example Code
See [example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java](https://github.com/Steveice10/MCAuthLib/blob/master/example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java)

## Building the Source
MCAuthLib uses Maven to manage dependencies. Simply run 'mvn clean install' in the source's directory.

## License
MCAuthLib is licensed under the **[MIT license](http://www.opensource.org/licenses/mit-license.html)**.

