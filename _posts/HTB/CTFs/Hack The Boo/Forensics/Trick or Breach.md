## CHALLENGE INFO
> Our company has been working on a secret project for almost a year.
> None knows about the subject, although rumor is that it is about an old Halloween legend where an old witch in the woods invented a potion to bring pumpkins to life, but in a more up-to-date approach. Unfortunately, we learned that malicious actors accessed our network in a massive cyber attack.
> Our security team found that the hack had occurred when a group of children came into the office's security external room for trick or treat.
> One of the children was found to be a paid actor and managed to insert a USB into one of the security personnel's computers, which allowed the hackers to gain access to the company's systems.
> We only have a network capture during the time of the incident.
> Can you find out if they stole the secret project?

---
We are provided with a zip file `forensics_trick_or_breach.zip` containing a pcap file called `capture.pcap`.
Opening the pcap file in wireshark we see that it only contains DNS traffic.
![alt text](TrickOrBreach1.png)
So going by the challenge info it looks like we need to gather some data out of these dns query responses. Googling for DNS exfiltration will yield a high amount of hits.
We now know how the secret project was exfiltrated from the infected machine. A small cheating pre knowledge was gained by playing  `HTB - Cyber Apocalypse CTF 2022`. Specifically completing the Forensics challenge `Automation`. That challenge had an almost identical DNS exfiltration taking place as part of the challenge.
As can be seen in the image below we are interested in this data being prepended as a sort of subdomain to this domain query.
![alt text](TrickOrBreach3.png)
This data can easily be carved out from the pcap file to a txt document by using the tshark tool using the following command.
`tshark -r capture.pcap -T fields -e dns.qry.name "dns.flags.response eq 1 and ip.src eq 147.182.172.189" | cut -d. -f1,4 > out.txt`
The following command will output this data after removing newlines, so that it becomes one large string of data.
```
504b0304140008080800a52c475500000000000000000000000018000000786c2f64726177696e67732f64726177696e67312e786d6c9dd05d6ec2300c07f013ec0e55de695a181343145ed04e300ee0256e1b918fca0ea3dc7ed14a36697b011e6dcb3ff9efcd6e74b6f84462137c23eab212057a15b4f15d230eef6fb395283882d76083c7465c90c56efbb41935adcfbca722ed7b5ea7b2117d8cc35a4a563d3ae0320ce8d3b40de420a6923aa909ce497656ceabea45f240089a7bc4b89f26e2eac1039a03e3f3fe4dd784b6350af7419d1cfa3821841662fa05f766e0aca907ae513d50fc01c67f82338a028736962ab8eb29d94842fd3c0938fe1af5ddc852becad55fc8dd14c7011d4fc32cb9437ac887b1265ebe93654677ee81b768031d81cbc8b838f8e3ddb12ac936b5282b6cb15edeadccb322b75f504b0708076269830501000007030000504b0304140008080800a52c475500000000000000000000000018000000786c2f64726177696e67732f64726177696e67322e786d6c9dd05d6ec2300c07f013ec0e55de695a181343145ed04e300ee0256e1b918fca0ea3dc7ed14a36697b011e6dcb3ff9efcd6e74b6f84462137c23eab212057a15b4f15d230eef6fb395283882d76083c7465c90c56efbb41935adcfbca722ed7b5ea7b2117d8cc35a4a563d3ae0320ce8d3b40de420a6923aa909ce497656ceabea45f240089a7bc4b89f26e2eac1039a03e3f3fe4dd784b6350af7419d1cfa3821841662fa05f766e0aca907ae513d50fc01c67f82338a028736962ab8eb29d94842fd3c0938fe1af5ddc852becad55fc8dd14c7011d4fc32cb9437ac887b1265ebe93654677ee81b768031d81cbc8b838f8e3ddb12ac936b5282b6cb15edeadccb322b75f504b0708076269830501000007030000504b0304140008080800a52c475500000000000000000000000018000000786c2f776f726b7368656574732f7368656574312e786d6ccd58ed72da38147d827d07d793e990d914636383a1402760039949d20c49bbb33f155b8037b6e5da7220fbf42b59f2974c02ddc976f64f620ee75e9d23dd2b248fbeec035f7a8671e2a1702cabed8e2cc1d041ae176ec6f2b787f9275396120c4217f8288463f90526f297c96fa31d8a9f922d84582209c2642c6f318e868a92385b1880a48d2218926fd6280e00261fe38d924431046e1614f88ad6e9f4940078a1cc320ce35372a0f5da73a0859c348021664962e8034ce4275b2f4af26cc1be912ef09c1825688ddb0e0a7826a2c051e0de819920b32628704e511480f8298d3e91941151f1e8f91e7ec97415699ec7721a87439ee3532183c60cc9f8c3e7c0cfc97b553f4d77633207caa0a67eaf1aff2e93da51545548a583e65c9c2e0b3845a6e0b434c58af012998cb29477f1648452ec7b21bc8ba5240dc8e4bf4ca18f766399142e0756de668b29a04c464a11973d7cf7e02ea93c4bb48c1f117aa21fae5c1a3419452084d2cb7d4456722cebb423308aaee11acfa0ef8fe54b43968083bd67780768473c228c5140bfcf3a0513681da3bf6148c74fa00f1d5a9c3c84a59892e2487ec470cd1e23314f219ccaaa3ee7dae75901923970d284042d21b3acca920bd720f5f10cf97f782ede124c6bf7ba05be42bb826cb4fb061dca417e92fde5d9f240590abc90fd07fbecff8e7da3b5f3b8c3111a8fd08a08553f12d2e521dd2244ef97f20ec7e83c462f87d1dadadb31068f318a98c1b1617a3ca4ff13c3983cc614e74c61939d2da20530988c62b493e22c325b148dd69bb8aa6424cab924a4847e56383015819908580cd00ac06640b700e6226321e65856180a915b68d698665da7d3f1aa684d14cd00b26a849610daf3a433529ee9dce42e18c3285d30a0570951eb213663f44b5b22b010932e1960366c75992d6df0a6ad6e163d286de540a951136c3519dd3ac3620cb553a1e882514e512b14a34e991fa0f4ea94c5014abf4e59560cd6a647e7abde7e63727496be2caa2947caba9b35108b237a59ac1c29176dde40160d64591dbd26dde04df696748305f74ae91c294b69c611b394ce91b21c6c86689d523a47ca4e5834906515a949ef15027b8c52995b8e742b8b690aa5c729d5a61b08b5c72946b5c984c6b439a79c9c3947faac5675b36bb485a08548311a946541116df70bdbfd86ed7ed3b62a6c0bb37ed3b72ab4a5d53f605c684cbbdf30deaf48663efbc77df65ff369163ecd864ff3049fe6019fc2ce6199272cb0d9f0691e5f609172c0b8f99af141617cd0303e38605cd8eb668303c685cdce1a1c302eec76f6a0617c201ad71ac645ca01e383d78cab9df267bdd3b09e436ff574cea9791748564eaa99175adfce4915f73954a9ef26b4ac41757bf440e3b92e0c6b07187e94302b4e1bd02c87caddd4e250b7dc4eed1c522ba239543dcc34a0656d44265aa91cc802186fb2737a2239280de94940aea0123bb66bc3599652c02d6db860bf3b651a7a4e0c5d8fde0280cf4eee985caff31bc0c218529584b55ea53e94f04b446e03704f6e5209bd9593b3fb7ecdee2652147b2826174c36a7f41a9afa6072796bb5beae5a679631fef82345f8f355489868431330e0a2fcee16617a4d89317419209d5fd0e08531c6c8052fadf30ba9f2e177f5fc7ca4e423919ac9446607d9039e8e58b58ca1d5b44aae7afe5552d854ab36c9198ddcb96380115939f823057ec5f72b867ead5cad2ab77b5c6e636dde4deea5315c9e5448ddaa64bda2700537f6fe066067dba2d5747ec1145a2884ece9fd4a616e0ce74db1d80be01d24dadc42ac5e154b77b18242e8b446f9b5eabd241c6bbc9ed0786773e3a38f3f3f7cb52effa4bd73a411a5373af1e73acd25bbd577e07b2e7bf92502dc8eef25589680efa3ddd407e153d65fc916edaec228c5374418d840de742888c86e37f33de74902a12bc110c35802d233f05328adc9f7520cc20d94eed3c7bfa083930f536338d53ae5cb0cb5b22da9931b183cc238f970363d3386e48fd629fca9c4575defafd18fb75062939d7be09b20068fa50de22afb797e5727ecc2f1735eecd281e74a241d942bd5bba84f37a9bcdbaf0fadab7b7bb522cfd6e583fdfdf2fa9bdd9a1be7e7a43269b55edddf7ebb99da2b8a5d48d7f6fca135b3afaf5b6c16d87bcdbc5269182f55ab51a0ffe102de6380d344426bb25a5e2201d28c9b90beee956b1b736d811a1d755169bd8bfb272f8a08566e64ff8b42a429a94d0fc32029cdd557f56d67273a529a9b450c76742f8c871ed9e1e22b975d398bd7fa937f00504b0708ab4dfad36d0600001a180000504b0304140008080800a52c475500000000000000000000000023000000786c2f776f726b7368656574732f5f72656c732f7368656574312e786d6c2e72656c738dcf4b0ac2301006e0137887307b93d6858834ed46846ea51e6048a60f6c1e24f1d1db9b8da2e0c2e5cccf7cc35f350f33b31b8538392ba1e40530b2cae9c90e12cedd71bd0316135a8db3b32461a1084dbdaa4e3463ca37719c7c6419b151c29892df0b11d5480623779e6c4e7a170ca63c86417854171c486c8a622bc2a701f597c95a2d21b4ba04d62d9efeb15ddf4f8a0e4e5d0dd9f4e385d001efb95826310c942470fedabdc3926716445d89af8af513504b0708ada8eb4db30000002a010000504b0304140008080800a52c475500000000000000000000000018000000786c2f776f726b7368656574732f7368656574322e786d6c9d96ed8ea3361486afa0f740a954ed4a9d101bc85709ab1966475da99546e9d76f0f98091ac0ac6d12d2abaf8d0133986ca3fe49e0e59ce73d36c7d8c1a7a6c8ad13a62c23e5de068ba56de132264956beeeed3fff78badbd816e3a84c504e4abcb72f98d99fc2ef8233a16fec8831b704a0647bfbc879b5731c161f7181d88254b8144f52420bc4c52d7d755845314adaa42277e072b9720a9495b622ece82d0c92a6598c1f495c17b8e40a42718eb8289f1db38af5b4a23170451653c248ca1731293a92a820767013e3b6a0cdbb828af8968a0a44dfeaea4e202b51c54b9667fcd2d635604e7bbba6e5ae63dc0d65c89c9df0df9d8abc0f6e80775bddc6646e9dedbbea1be0ff3f12583a004c501e32e7e2f6b2503c908adb30c31be95a240c5ae4330d0352f33c2bf133b5585d88c9bf3ce09c9cf7b668dc4e3864af472e05270c9c21afbdf82bc36736bab6641bbf10f2266fbe2432290c2a5462ebf27b25dee4def6e48ae0a4fa15a73cc279beb7ef7ddb4231cf4ef819c915f1423827857cdeae142ea494927f7029fd19ce712c9bb34b518807d11cec2bc5a9baaca69ca17059d6f8baaffda96d40310771cd44d22f580d19d856825354e73c22f9df59c28f42838b953be807721e82fdc5da975631c959fbdbd1fa44db2ab252fda3a6fd3fab2770d1e7cd67c02e030e19aefb1f296e97e24e4d1c555d3bea47c451185072b6689bd98e02ca17349d06e12463ee451093f74e273c4c854809b0b512e4010f151e6e17d0bfce8753be125c310c11c744dc2984cbc039c981f4962a666358ba3759bacac1d39e8332f20413cf71d63b534f997a8b6f587a2ad9d7969db2d2f3388e7967e077efe95b06be9a468d7be894f5684c9bc99054080486e36ae0ae5408d4dc4e19bf1f309dab2e666d80d703786d80d733607f025e5f036f06f0c6002bc55deba9de5cc36c07ccd6c028c5dd68ccf61a062cf5fa591a20538a7a6906355a8ac0441952d44b3328a851d0441952d44b332857a35c136548512fcda03c8df24c942145bd3483f235ca37518614f5d20c4a2f0160ae01538ac0d59e07bae981d9f5a61481ab5d0e749b03b3cf4d2902573b1de8560766af9b5204ae763bd4dd0ecd6e37a5089addee8cb6a798944926777c94ab5d9a8ba374bfdbdffbbb4819a6873ac716bf5462e7c78d383531790217fb7493ca738868b88a66848ac3a4fa50ca23679da3f0805f3f37bf211e1f3f7cf8e1f0f9e9fb8f3ffdf8b526fce747713c57571f03a78f161f9fd6a8dd4767ea0a8384a2b32c90ee32614bbf24ea7b3a1cefc37f01504b0708ef4afc5bab030000220c0000504b0304140008080800a52c475500000000000000000000000023000000786c2f776f726b7368656574732f5f72656c732f7368656574322e786d6c2e72656c738dcf4b0ac2301006e0137887307b93b60b1169da8d08dd4a3dc0904c1fd82621898fdede6c140b2e5ccefccc37fc65fd9c2776271f466b24e43c034646593d9a5ec2a53d6df7c04244a371b286242c14a0ae36e599268ce9260ca30b2c2126481862740721821a68c6c0ad239392cefa19631a7d2f1caa2bf6248a2cdb09ff6d40b53259a325f846e7c0dac5d13fb6edba51d1d1aadb4c26fe7821b4c7472a9648f43d45099cbf779fb0e0890551956255b17a01504b07088501f515b40000002a010000504b0304140008080800a52c475500000000000000000000000014000000786c2f736861726564537472696e67732e786d6c75935f8ed33010c64fc01d4679a7699b08219464c5b25a2d1245882dcf956b4f13d3646c3c932d0b42e21a5c8f93e0047889e1214afc1b7f9e3ff95c5d7d1e7a78c0c0d6519d6d56eb0c90b43396da3afbb0bf7dfa3c03164546f58eb0ce1e91b3abe649c52c10a5c475d689f81779cebac341f1ca79a41839b9302889cbd0e6ec032ac31da20c7dbe5daf9fe583b294817623499d6d639291eca7115ffd01dbaca9d8369534ef515b8ff092d9b6342049954b53e553f0f786d704d25986f9f8f88901414dcfac40332188ed043436ca19dc69467ea433d2f402461da2d607f711b5ac9619eec7e3c497f8ff25dd8b929197746f07fcc7ce20609424919b11c15192934cc0cb926ee0d6f67dec20b6a6e084448fc0a4cec9a17156b1c9380a4eaa7b6bf579c90a7863bfa8607e7effc1d0639b8a9c4cee088226d55e2b814b1c7ca2dad9b4b202ee54dfbb0bc65fa23beb13d14db4df92ddedafbfeeca76a30fba245acbc187e2a120399852cac33114a5eebe25233f5befd37af7a806d8e1708c77212978c67f8df36e36cee49bd43079bc17cd2f504b070841df7c709501000055030000504b0304140008080800a52c47550000000000000000000000000d000000786c2f7374796c65732e786d6ce55ad9929b3814fd82f9074aef69796b2f294caae3694fcd4bf2d09daa799541d85440a240ced8f9fab9926c83dba20318bc64e8aa366839f71c491749e8da9f365168fda0491a703645dd870eb22873b917b0e5147d7b9d7f18232b15847924e48c4ed196a6e893f3879d8a6d485f56940a0b10583a452b21e28f18a7ee8a46247de0316590e3f32422021e93254ee384122f9595a210f73a9d218e48c09046f8b8e90e887b8213056ec253ee8b07974798fb7ee0d253a4099e60e2ee91a25318039d8824dfd7f107808d890816411888ad62851c9bada3792452cbe56b26a05d0e4996fef9db83c4e100591a70c63d689b087b780b17c28e8d77088eed739603ea219de2d8e94feb070921a9038d0e355c1ef2c44a968b299acf3bea92c98c4454177c4a02122a6c0d700cd3eb1960f4f506067413265685484642462423a105cea0fac392da9e5dce3874357903874b911baaeb18f12b74b8f542585a4de7643e7b7c1e57d5d91d9ca9b3b0b58fca9451f74b0ac555f38a7ae728523f72e807617818fa8f48273836b89ba0099bc383b5bb7fddc6e0400c5e311a4695fb45e93058aec45f09d996af92f230f0248fe5ccdcdc8ba20c9cc33cdbda64a25bf1c4da3ea3416bb3d9d368343258cb328cd6d40ff4e182271e4c0f87175807edd3f0fec6b143ea0b4b4d09532456f04a2f1ecfb2a86327b2ef4ad650651d5bf0b864052829a909c1a39235746175a305d516761596f7d29af7d185edb766658e395f2dc93157a31cc75c857a1c6fd3c7fbf2eff6074846f37f2fec1d97deddc0ace4d2307c9120fff8478bf48d6fe93272810e7b193989ed6f614db2bbcdd6f0f040e238dc3ec162824554c3e8a439d74f9249de9c369eb3db9fd433bcf14b32706cb2cfb4e4be07f6665fa52955395d2501fbfecae78150cfb09713b01a8395996e3e64fd9b90f8956e54b614b3f1dfd0ed66747b19dd6e55ba9fb92675a00f988d8981d19357d2ada2a477b61203f7154f829f902ec949ef41bf8d1ae5d92dc8e919e5f4db90d338f7bed1a307ef722f228a4bb5cbe39d0eda418b2d657688e19db6d4a351cde8cafee042799adc16fdb33ae3d605557fdd965634cc14f53345e31b98d8af46fd42ce7141fa97718e2b096ad13946c6896ad2c8445507bba1d1db98d6b6bca9958e69cd776e8961813354a0d83dda83aa03acda2cf5d39775b4a0c95c9d8235c57ddca267d6c16ed333afc8a7ba675e906c4dcfbc12433dba2b30ba0f479cb4e88875b06bf654e5717e416e27e3fc9608bd33accd8cee6358177cef3cff83e725be449977a9ad7c2d6a791f31b8df2d69a3d42fd4f2bff9aa0aef4e6572674347274387d48c860c6299a22ff2dd12226bb10e4211309d7774e80398dec63f0a64f1a4c92c6ae6cd49ea3e4a661f5d5329eae5105c8195919ca582589c86ad04a7513fe30be8c962b8ca5929087779567f8670972cc318ee52c412d725f279f8e7e8696c209265942122ffc3f8c359bca5f31f504b0708cf9f9daa39040000b4290000504b0304140008080800a52c47550000000000000000000000000f000000786c2f776f726b626f6f6b2e786d6c9d93d16a833014869f60ef20b96fa35d373aa996c118f4626317db03c478aca126919cd4d9b7dfd15a695718b22b13cdffe523f95d6f5a5d050d3854d6242c9a872c00236daecc2e615f9fafb3150bd00b938bca1a48d811906dd2bbf5b775fbccda7d407983092bbdaf63ce5196a005ce6d0d86be14d669e169ea761c6b0722c712c0eb8a2fc2f0916ba10c3b11623785618b424978b1f2a0c1f813c441253cd963a96a3cd3747b83d34a3a8bb6f07369f5402203c9a195d00badae84b49c62a485db1fea19216bb2c854a5fcb1f71a314dc20ecec40363366a749998f68f1b5d9d17b7d1729af7cd613ef1a72bfb367af81f290a7914fd422dc5ed594cd7127224e96998f146868aa463dd3e1c4fd73d1f8767d74e4fc56c14aaac021618a169fa8ca876a66b0975a25fb8cda9df2c70b1a281dbe6f78cff8d78039dd18f71115f5cc4975d9c9f5572289481fc9d8248efa5a864afcacfe2e90f504b0708d09a438a5b0100006a030000504b0304140008080800a52c47550000000000000000000000001a000000786c2f5f72656c732f776f726b626f6f6b2e786d6c2e72656c73bd92c16ac3300c869f60ef60745f9ca4638c51a79731e8b5cb1ec0d84a1c9ad8c6d2dae5ede731b6a550ca0e652721197dff87f07af33e8de2808986e01554450902bd0976f0bd82d7f6f9f60104b1f6568fc1a382190936cdcd7a87a3e6bc436e882432c49302c71c1fa524e370d25484883ebf74214d9a739b7a19b5d9eb1e655d96f7322d19d09c30c5d62a485b5b8168e7887f6187ae1b0c3e05f336a1e7331192781eb3bf6875ea91157cf545e6803c1f5f5f35dee984f685533eeed26239be24b3baa6cc31a43d3944fe15f9197daae6525d92b9fb6799fa5b469e7cbde603504b07089f22ace0e2000000c2020000504b0304140008080800a52c47550000000000000000000000000b0000005f72656c732f2e72656c738dcf410e82301005d013788766f65270618ca1b031266c0d1ea0b6432140a769abc2eded528d0b9793f9f37ea6ac9779620ff461202ba0c872606815e9c11a01d7f6bc3d000b515a2d27b22860c50075b5292f38c9986e423fb8c0126283803e4677e43ca81e6719327268d3a6233fcb98466fb8936a9406f92ecff7dcbf1b507d98acd1027ca30b60edeaf01f9bba6e507822759fd1c61f155f89244b6f300a5826fe243fde88c62ca1c0ab927f3c58bd00504b0708a46fa120b200000028010000504b0304140008080800a52c4755000000000000000000000000130000005b436f6e74656e745f54797065735d2e786d6cc554db6a023110fd82fec392d762a23e94525c7de8e5b12dd47ec034997583b99189bafbf7cdae5aa858a8a0f894999c99734e26219359634db1c648dabb928df89015e8a457da2d4af6397f19dcb382123805c63b2c598bc466d39bc9bc0d48456e7654b23aa5f02004c91a2d10f7015d462a1f2da49cc685082097b040311e0eef84f42ea14b83d471b0e9e4092b5899543c6ef73bea924108464b48d997c864ac786e32b8b5d9e5e21f7d6ba70ecc0c76467844d3d750ad03dd1e0a64943a85b73c99a8159e24e1ab4a4b545eae6c6ee1142282a21a3159c3373e2efb78abf90e31bd82cda4a231e20724d12f23be3be9957d8c2fe7836a88a83e52cc0f8e8e79f955704e1f2ac226731ed3dc41b40fce7a0f27e85e72eea935787ce03d72c91bcf2bb7a0dd5f4fefcbfbe55e5ff41fcdf41b504b0708732e8eb934010000a8040000504b01021400140008080800a52c4755076269830501000007030000180000000000000000000000000000000000786c2f64726177696e67732f64726177696e67312e786d6c504b01021400140008080800a52c475507626983050100000703000018000000000000000000000000004b010000786c2f64726177696e67732f64726177696e67322e786d6c504b01021400140008080800a52c4755ab4dfad36d0600001a180000180000000000000000000000000096020000786c2f776f726b7368656574732f7368656574312e786d6c504b01021400140008080800a52c4755ada8eb4db30000002a010000230000000000000000000000000049090000786c2f776f726b7368656574732f5f72656c732f7368656574312e786d6c2e72656c73504b01021400140008080800a52c4755ef4afc5bab030000220c000018000000000000000000000000004d0a0000786c2f776f726b7368656574732f7368656574322e786d6c504b01021400140008080800a52c47558501f515b40000002a01000023000000000000000000000000003e0e0000786c2f776f726b7368656574732f5f72656c732f7368656574322e786d6c2e72656c73504b01021400140008080800a52c475541df7c7095010000550300001400000000000000000000000000430f0000786c2f736861726564537472696e67732e786d6c504b01021400140008080800a52c4755cf9f9daa39040000b42900000d000000000000000000000000001a110000786c2f7374796c65732e786d6c504b01021400140008080800a52c4755d09a438a5b0100006a0300000f000000000000000000000000008e150000786c2f776f726b626f6f6b2e786d6c504b01021400140008080800a52c47559f22ace0e2000000c20200001a0000000000000000000000000026170000786c2f5f72656c732f776f726b626f6f6b2e786d6c2e72656c73504b01021400140008080800a52c4755a46fa120b2000000280100000b00000000000000000000000000501800005f72656c732f2e72656c73504b01021400140008080800a52c4755732e8eb934010000a804000013000000000000000000000000003b1900005b436f6e74656e745f54797065735d2e786d6c504b0506000000000c000c0036030000b01a00000000
```
A useful knowledge is to know the magic byte values for some common file types.
Magic bytes usually occupy the first four bytes of a given file type `504b` in this case indicates that this is a zip file we have carved out from the DNS exfiltration.
https://www.netspi.com/blog/technical/web-application-penetration-testing/magic-bytes-identifying-common-file-formats-at-a-glance/

In order to convert this string of data into an actual file we can interact with, we can use the great tool CyberChef.
Using the following recipe `[{"op":"Find / Replace","args":[{"option":"Regex","string":"\\n"},"",true,false,true,false]},{"op":"From Hex","args":["Auto"]}]`
We can then insert the contents of `out.txt` into Cyberchef and get a readily downloadable zip file.
The recipe just removes new lines and then converts the string from hex to it's raw data representation.

When opening the now downloaded zip file, we are then presented with the following data.
![alt text](TrickOrBreach4.png)
This looks like the contents of a xlsx document. All microsoft office documents using the new `docx, xlsx, pptx` etc. file formats are actually zip files.
So now closing the zip file and renaming it to xlsx and opening it, we are then presented with the flag.
![alt text](TrickOrBreach2.png)
`HTB{M4g1c_c4nn0t_pr3v3nt_d4t4_br34ch}`