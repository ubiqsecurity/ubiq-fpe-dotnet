# Format-preserving encryption in C# (dotnet)

An implementation of the NIST-approved FF1 and FF3-1 algorithms in C# (dotnet).

This implementation conforms (as best as possible) to
[Draft SP 800-38G Rev. 1][800-38g1]. The implementation passes all tests
specified by NIST in their Cryptographic Standards and Guidelines
[examples for FF1][ff1-examples]; however, no official examples/samples exist
(or are known) for FF3-1. FF3 is not implemented as NIST has officially
deprecated its use in light of recent [cryptanalysis][ff3-cryptanalysis]
performed on it.

# Building

The library is dependent on [Bouncy Castle](https://www.bouncycastle.org/).

If building the ubiq-dotnet library from source, the ubiq-dotnet solution assumes the .NET Framework 4.6.1 for Windows, .NET Core 2.0 or later, and .NET Standard 2.0 or later

With those dependencies installed, the library can be built using PowerShell or Visual Studio 2017 or later:

#### Compiling using PowerShell
From within the cloned local git repository folder, use a PowerShell window to run:
```sh
PS > dotnet build
```
The above command will build the library as well as the unit tests.

#### Compiling using Visual Studio Environment
-   Visual Studio 2017 or newer
-   In the Visual Studio Installer, make sure the following items are checked in the *Workloads* category:
    - .NET desktop development
    - .NET Core cross-platform development
-   If building the ubiq-dotnet library from source, the ubiq-dotnet solution assumes the .NET Framework 4.6.1 for Windows, .NET Core 2.0 or later, and .NET Standard 2.0 or later.

From the Build menu, execute *Rebuild Solution* to compile all projects.

#### Requirements to Use Ubiq-Security library
-   Visual Studio 2017 or newer with one of the following development environments
    - .NET Framework (4.6.1 or newer) desktop development
    - .NET Core (2.0 or newer) cross-platform development

# Testing

To run the tests:
```sh
PS> dotnet test tests/UbiqSecurity.Fpe.UnitTests/bin/Debug/UbiqSecurity.Fpe.UnitTests.dll
```
As described above, the unit tests for FF1 come from the NIST guidelines. As
no such guidelines are available for FF3-1, the unit tests verify only that
the encryption and decryption implementations are compatible with each other.

# Documentation

The interfaces are documented in the source 
[files](src/UbiqSecurity.Fpe).

### About alphabets and the radix parameter

The interfaces operate on strings, and the radix parameter determines which
characters are valid within those strings, i.e. the alphabet. For example, if
your radix is 10, then the alphabet for your plain text consists of the
characters in the string "0123456789". If your radix is 16, then the
alphabet is the characters in the string "0123456789abcdef".

More concretely, if you want to encrypt, say, a 16 digit number grouped into
4 groups of 4 using a `-` as a delimiter as in `0123-4567-8901-2345`, then you
would need a radix of at least 11, and you would need to translate the `-`
character to an `a` (as that is the value that follows `9`) prior to the
encryption. Conversely, you would need to translate an `a` to a `-` after
decryption.

This mapping of user inputs to alphabets defined by the radix is not performed
by the library and must be done prior to calling the encrypt and after calling
the decrypt functions.

A radix of up to 36 is supported, and the alphabet for a radix of 36 is
"0123456789abcdefghijklmnopqrstuvwxyz".

### Tweaks

Tweaks are very much like Initialization Vectors (IVs) in "traditional"
encryption algorithms. For FF1, the minimun and maximum allowed lengths of
the tweak may be specified by the user, and any tweak length between those
values may be used. For FF3-1, the size of the tweak is fixed at 7 bytes.

### Plain/ciphertext input lengths

For both FF1 and FF3-1, the minimum length is determined by the inequality:
- radix<sup>minlen</sup> >= 1000000

or:
- minlen >= 6 / log<sub>10</sub> radix

Thus, the minimum length is determined by the radix and is automatically
calculated from it.

For FF1, the maximum input length is
- 2<sup>32</sup>

For FF3-1, the maximum input length is
- 2 * log<sub>radix</sub> 2<sup>96</sup>

or:
- 192 / log<sub>2</sub> radix

## Examples

The [unit test code](tests/Ubiqsecurity.Fpe.UnitTests) provides the best
and simplest example of how to use the interfaces.

### FF1
```csharp
    /*
     * key is a byte array whose length must be 16, 24, or 32
     * twk is a byte array whose length must be between the minimum
     *      and maximum specified in the arguments to the constructor
     *
     * radix and PT are "user inputs"
     */
    string out;
    FF1 ctx;

    ctx = new FF1(key, twk, 0, 0, radix);

    out = ctx.encrypt(PT);
    out = ctx.decrypt(out);
```
### FF3-1
```csharp
    /*
     * key is a byte array whose length must be 16, 24, or 32
     * twk is a byte array whose length must be 7
     *
     * radix and PT are "user inputs"
     */
    string out;
    FF3_1 ctx;

    ctx = new FF3_1(key, twk, radix);

    out = ctx.encrypt(PT);
    out = ctx.decrypt(out);
```

[800-38g1]:https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
[ff1-examples]:https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
[ff3-cryptanalysis]:https://csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3