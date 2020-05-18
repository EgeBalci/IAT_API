# IAT API
Assembly block for finding and calling the windows API functions inside import address table(IAT) of the running PE file.


Design of the block is inspired by Stephen Fewer's [block_api](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm) and Josh Pitts's 2017 [DEFCON](https://github.com/secretsquirrel/fido/blob/master/Defcon_25_2017.pdf) talk. iat_api finds the addresses of API functions by parsing the `_IMAGE_IMPORT_DESCRIPTOR` structure entries inside the import table of the PE file. It first calculates the ROR(13) hash of the (module name + function name) and compares with the hash passed to block. If the hash matches it calls the function with the parameters passed to block.

[![Description](https://github.com/EgeBalci/iat_api/raw/master/img/flow.png)]()

One of the main objectives while designing iat_api was bypassing exploit mitigation techniques used inside EMET, Windows Defender and similar security products. Using import address table(IAT) entries instead of export address table(EAT) makes it possible to find API addresses without reading the KERNEL32/NTDLL and KERNELBASE therefore bypasses the EMET's Export Address Filtering(EAF) and Export Address Filtering Plus(EAF+) mitigations. Also after finding the wanted API addresses iat_api makes a CALL to the API instead of jumping or returning inside it therefore bypasses EMET's caller checks. Changing the rotation value used for calculating the function name hash may help bypassing anti virus products that are using ROR13 hashes as signature detection.

<strong>IMPORTANT !!</strong> 
- The function that is called with iat_api must be imported by the PE file or it will crash.

## Example

Here is a example MessageBox shellcode using the iat_api.

[![Description](https://github.com/EgeBalci/IAT_API/raw/master/img/Example.png)]()

Here is a 64 bit example MessageBox shellcode using the iat_api.

[![Description](https://github.com/EgeBalci/iat_api/raw/master/img/Example64.png)]()