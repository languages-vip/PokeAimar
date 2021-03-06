local ITEM_NAME_BY_ID = {
    [3584] = "pear",
    [3585] = "red apple",
    [3586] = "orange",
    [3587] = "banana",
    [3588] = "blueberry",
    [3589] = "coconut",
    [3590] = "cherry",
    [3591] = "strawberry",
    [3592] = "grapes",
    [3593] = "melon",
    [3594] = "pumpkin",
    [3595] = "carrot",
    [3596] = "tomato",
    [3597] = "corncob",
    [130] = "cookie",
    [3599] = "candy cane",
    [3607] = "cheese",
    [6499] = "soul coin",
    [6569] = "candy",
    [6574] = "bar of chocolate",
    [229] = "ice cream cone (crispy chocolate chips)",
    [7373] = "ice cream cone",
    [7374] = "ice cream cone",
    [7375] = "ice cream cone (chilly cherry)",
    [7376] = "ice cream cone",
    [7377] = "ice cream cone (blue-barian)",
    [6393] = "birthday cake",
    [3598] = "exploding cookie",
    [3607] = "scarab cheese",
    [6393] = "birthday cake",
    [7372] = "ice cream cone",
    [11042] = "moltres feather",
    [11043] = "zapdos feather",
    [11044] = "articuno feather",
    [11045] = "pincer horn",
    [11046] = "harden shell",
    [11047] = "gyarados tail",
    [11048] = "pot of lava",
    [11050] = "bag of polen",
    [11051] = "bulb",
    [11052] = "leaf",
    [11056] = "",
    [11057] = "razor fang",
    [11058] = "hull",
    [11059] = "big nail",
    [11060] = "microphone",
    [11061] = "water gem",
    [11062] = "fire element",
    [11063] = "seed",
    [11064] = "screw",
    [11065] = "bottle of poison",
    [11067] = "tangela hair",
    [11068] = "mr. mime cloth",
    [11069] = "scyther razor",
    [11070] = "jynx clothes",
    [11071] = "yellow tail",
    [11072] = "",
    [11073] = "water pendant",
    [11074] = "pot of moss mug",
    [11075] = "sharp beak",
    [11076] = "bitten apple",
    [11077] = "syrup",
    [11078] = "tooth",
    [11079] = "electrizer",
    [11080] = "sandbag",
    [11081] = "horn",
    [11082] = "comb",
    [11083] = "tail",
    [11084] = "fur",
    [11085] = "bat wing",
    [11086] = "mushroom",
    [11087] = "insect antenna",
    [11088] = "",
    [11089] = "amulet coin",
    [11090] = "ball of wool",
    [11091] = "ruby",
    [11092] = "psyduck mug",
    [11093] = "",
    [11094] = "box gloves",
    [11095] = "",
    [11096] = "twisted spoon",
    [11097] = "shadow orb",
    [11098] = "tiara",
    [11099] = "stone orb",
    [11100] = "slowpoke tail",
    [11101] = "magnet",
    [11102] = "stick",
    [11103] = "feather",
    [11104] = "ice cub",
    [11105] = "black sludge",
    [11106] = "shell bell",
    [11107] = "reaper cloth",
    [11108] = "piece of onix",
    [11109] = "linearly guided hypnose pendant",
    [11110] = "crab claw",
    [11111] = "thick club",
    [11112] = "bandage",
    [11113] = "tongue",
    [11115] = "egg",
    [11116] = "thorn",
    [11163] = "churros with white chocolate",
    [11164] = "churros with milk candy",
    [11165] = "churros with chocolate",
    [11166] = "burger",
    [11167] = "potato chip",
    [11168] = "hot dog",
    [11169] = "sushi",
    [11170] = "potato",
    [11171] = "pizza",
    [11172] = "coconut water",
    [11173] = "lemonade",
    [11190] = "Flame Plate",
    [11191] = "Splash Plate",
    [11192] = "Meadow Plate",
    [11193] = "Love Plate",
    [11194] = "Mind Plate",
    [11195] = "Stone Plate",
    [11196] = "Toxic Plate",
    [11197] = "Icicle Plate",
    [11198] = "Zap Plate",
    [11201] = "Draco Plate",
    [11202] = "Insect Plate",
    [11203] = "Dread Plate",
    [11204] = "Fist Plate",
    [11205] = "pokemon health potion",
    [11206] = "pokemon great health potion",
    [11207] = "pokemon ultra health potion",
    [11208] = "pokemon super health potion",
    [11209] = "pokemon revive",
    [11210] = "pokemon antidote",
    [11211] = "pokemon elixir",
    [11214] = "pidgeot doll",
    [11215] = "mew doll",
    [11216] = "poliwrath doll",
    [11217] = "pikachu doll",
    [11218] = "seel doll",
    [11219] = "lapras doll",
    [11220] = "lugia doll",
    [11221] = "articuno doll",
    [11222] = "zapdos doll",
    [11223] = "moltres doll",
    [11224] = "psyduck doll",
    [11225] = "mewtwo doll",
    [11226] = "kabuto doll",
    [11227] = "slowbro doll",
    [11228] = "omanyte doll",
    [11229] = "chansey doll",
    [11230] = "cubone doll",
    [11231] = "jigglypuff doll",
    [11232] = "bulbasaur doll",
    [11233] = "raichu doll",
    [11579] = "seed of cheri berry",
    [12028] = "seed of chesto berry",
    [12029] = "seed of pecha berry",
    [12030] = "seed of rawst berry",
    [12031] = "seed of leppa berry",
    [11581] = "cheri berry",
    [11582] = "chesto berry",
    [11583] = "pecha berry",
    [11584] = "rawst berry",
    [11585] = "leppa berry",
    [11599] = "yellow poke ball backpack",
    [11600] = "blue poke ball backpack",
    [11601] = "gray poke ball backpack",
    [11602] = "brown poke ball backpack",
    [11603] = "purple poke ball backpack",
    [11604] = "green poke ball backpack",
    [11605] = "red poke ball backpack",
    [11606] = "pikachu backpack",
    [11607] = "white poke ball backpack",
    [11608] = "orange poke ball backpack",
    [11609] = "mach bike",
    [11677] = "big mushroom",
    [11678] = "flame orb",
    [11679] = "gracidea",
    [11680] = "lava cookie",
    [11681] = "magma stone",
    [11682] = "magmarizer",
    [11683] = "metal spike",
    [11684] = "revival herb",
    [11685] = "squirtle watering can",
    [11685] = "squirtle watering can",
    [12025] = "pokemon energy potion",
    [12027] = "Earth Plate",
    [12145] = "pokemon great energy potion",
    [12297] = "stamina recover",
    [12782] = "star ball paint ticket",
    [12783] = "yereblu ball paint ticket",
    [12790] = "enchanted staff",
    [12791] = "light wand",
    [12792] = "pumpkin ball paint ticket",
    [12793] = "skull ball paint ticket",
    [12796] = "rare candy",
    [12797] = "onigiri",
    [12798] = "ape hair",
    [12799] = "bamboo leaves",
    [12800] = "bunch of ripe rice",
    [12801] = "bunch of sugar cane",
    [12802] = "bunch of wheat",
    [12803] = "bunch of winterberries",
    [12804] = "burning heart",
    [12805] = "colourful feather",
    [12806] = "",
    [12807] = "coral comb",
    [12808] = "crab pincer",
    [12809] = "cursed hand",
    [12810] = "cutting fang",
    [12811] = "downy feather",
    [12812] = "elemental spike",
    [12813] = "energy soil",
    [12814] = "essence of a bad dream",
    [12815] = "eternal flames",
    [12816] = "exquisite silk",
    [12817] = "light feather",
    [12818] = "flawless ice crystal",
    [12819] = "frost charm",
    [12820] = "frostbite herb",
    [12821] = "frozen heart",
    [12822] = "frozen tear",
    [12823] = "gear wheel",
    [12824] = "giant pincer",
    [12825] = "heavy stone",
    [12826] = "huge chunk of crude iron",
    [12827] = "ice crystal",
    [12828] = "giant ice cube",
    [12829] = "icicle",
    [12830] = "mouldy cheese",
    [12831] = "hard nail",
    [12832] = "petrified scream",
    [12833] = "piece of royal steel",
    [12834] = "pincer",
    [12835] = "royal feather",
    [12836] = "sample of sand wasp honey",
    [12837] = "scarab cheese",
    [12838] = "shadow rock",
    [12839] = "shard",
    [12840] = "spool of yarn",
    [12841] = "strong pincers",
    [12842] = "blastoise hull",
    [12843] = "leaf pendant",
    [12844] = "venom pendant",
    [12845] = "night orb",
    [12846] = "fire pendant",
    [12847] = "fire orb",
    [12848] = "pot of water",
    [12849] = "white orb",
    [12850] = "black diamond",
    [12851] = "black orb",
    [12852] = "rare sandbag",
    [12853] = "green orb",
    [12861] = "shiny harden shell",
    [12862] = "shiny gyarados tail",
    [12863] = "shiny pot of lava",
    [12864] = "shiny bulb",
    [12865] = "shiny leaf",
    [12866] = "shiny razor fang",
    [12867] = "shiny hull",
    [12868] = "shiny microphone",
    [12869] = "shiny water gem",
    [12870] = "shiny fire element",
    [12871] = "shiny seed",
    [12872] = "shiny screw",
    [12873] = "shiny bottle of poison",
    [12874] = "shiny tangela hair",
    [12875] = "shiny mr. mime cloth",
    [12876] = "shiny scyther razor",
    [12877] = "shiny jynx clothes",
    [12878] = "shiny yellow tail",
    [12879] = "shiny water pendant",
    [12880] = "shiny pot of moss mug",
    [12881] = "shiny sharp beak",
    [12882] = "shiny bitten apple",
    [12883] = "shiny syrup",
    [12884] = "shiny tooth",
    [12885] = "shiny electrizer",
    [12886] = "shiny rare sandbag",
    [12887] = "shiny horn",
    [12888] = "shiny tail",
    [12889] = "shiny fur",
    [12890] = "shiny bat wing",
    [12891] = "shiny insect antenna",
    [12892] = "shiny bug venom",
    [12893] = "shiny amulet coin",
    [12894] = "shiny ball of wool",
    [12895] = "shiny ruby",
    [12896] = "shiny psyduck mug",
    [12897] = "shiny blue scarf",
    [12898] = "shiny box gloves",
    [12899] = "shiny iron bracelets",
    [12900] = "shiny twisted spoon",
    [12901] = "shiny shadow orb",
    [12902] = "shiny tiara",
    [12903] = "shiny stone orb",
    [12904] = "shiny slowpoke tail",
    [12905] = "shiny magnet",
    [12906] = "shiny stick",
    [12907] = "shiny feather",
    [12908] = "shiny ice cub",
    [12909] = "shiny black sludge",
    [12910] = "shiny shell bell",
    [12911] = "shiny reaper cloth",
    [12912] = "shiny piece of onix",
    [12913] = "shiny linearly guided hypnose pendant",
    [12914] = "shiny crab claw",
    [12915] = "shiny thick club",
    [12916] = "shiny bandage",
    [12917] = "shiny tongue",
    [12918] = "shiny azure flute",
    [12919] = "shiny thorn",
    [12920] = "shiny ape hair",
    [12921] = "shiny bamboo leaves",
    [12922] = "shiny bunch of ripe rice",
    [12923] = "shiny bunch of sugar cane",
    [12924] = "shiny bunch of wheat",
    [12925] = "shiny bunch of winterberries",
    [12926] = "shiny burning heart",
    [12927] = "shiny colourful feather",
    [12928] = "shiny comb",
    [12929] = "shiny coral comb",
    [12930] = "shiny crab pincer",
    [12931] = "shiny cursed hand",
    [12932] = "shiny cutting fang",
    [12933] = "shiny downy feather",
    [12934] = "shiny elemental spike",
    [12935] = "shiny energy soil",
    [12936] = "shiny essence of a bad dream",
    [12937] = "shiny eternal flames",
    [12938] = "shiny exquisite silk",
    [12939] = "shiny light feather",
    [12940] = "shiny flawless ice crystal",
    [12941] = "shiny frost charm",
    [12942] = "shiny frostbite herb",
    [12943] = "shiny frozen heart",
    [12944] = "shiny frozen tear",
    [12945] = "shiny gear wheel",
    [12946] = "shiny giant pincer",
    [12947] = "shiny heavy stone",
    [12948] = "shiny huge chunk of crude iron",
    [12949] = "shiny ice crystal",
    [12950] = "shiny ice cube",
    [12951] = "shiny icicle",
    [12952] = "shiny mouldy cheese",
    [12953] = "shiny hard nail",
    [12954] = "shiny petrified scream",
    [12955] = "shiny piece of royal steel",
    [12956] = "shiny pincer",
    [12957] = "shiny royal feather",
    [12958] = "shiny sample of sand wasp honey",
    [12959] = "shiny scarab cheese",
    [12960] = "shiny shadow rock",
    [12961] = "shiny shard",
    [12962] = "shiny spool of yarn",
    [12963] = "shiny strong pincers",
    [12964] = "big feather",
    [12965] = "insect skin",
    [12966] = "resistant fabric",
    [12967] = "fancy fabric",
    [12968] = "healing oil",
    [12969] = "lightweight fabric",
    [12970] = "long silk",
    [12971] = "old bandage",
    [13117] = "aspear berry",
    [13118] = "oran berry",
    [13119] = "persim berry",
    [13120] = "lum berry",
    [13121] = "sitrus berry",
    [13142] = "seed of aspear berry",
    [13143] = "seed of oran berry",
    [13144] = "seed of persim berry",
    [13145] = "seed of lum berry",
    [13146] = "seed of sitrus berry",
    [15688] = "TM 01",
    [15689] = "TM 02",
    [15690] = "TM 03",
    [15691] = "TM 04",
    [15692] = "TM 05",
    [15693] = "TM 06",
    [15694] = "TM 07",
    [15695] = "TM 08",
    [15696] = "TM 09",
    [15697] = "TM 10",
    [15698] = "TM 11",
    [15699] = "TM 12",
    [15700] = "TM 13",
    [15701] = "TM 14",
    [15702] = "TM 15",
    [15703] = "TM 16",
    [15704] = "TM 17",
    [15705] = "TM 18",
    [15706] = "TM 19",
    [15707] = "TM 20",
    [15708] = "TM 21",
    [15709] = "TM 22",
    [15710] = "TM 23",
    [15711] = "TM 24",
    [15712] = "TM 25",
    [15713] = "TM 26",
    [15714] = "TM 27",
    [15715] = "TM 28",
    [15716] = "TM 29",
    [15717] = "TM 30",
    [15718] = "TM 31",
    [15719] = "TM 32",
    [15720] = "TM 33",
    [15721] = "TM 34",
    [15722] = "TM 35",
    [15723] = "TM 36",
    [15724] = "TM 37",
    [15725] = "TM 38",
    [15726] = "TM 39",
    [15727] = "TM 40",
    [15728] = "TM 41",
    [15729] = "TM 42",
    [15730] = "TM 43",
    [15731] = "TM 44",
    [15732] = "TM 45",
    [15733] = "TM 46",
    [15734] = "TM 47",
    [15744] = "heart seal A",
    [15745] = "heart seal B",
    [15746] = "heart seal C",
    [15747] = "heart seal D",
    [15748] = "heart seal E",
    [15749] = "heart seal F",
    [15750] = "star seal A",
    [15751] = "star seal B",
    [15752] = "star seal C",
    [15753] = "star seal D",
    [15754] = "star seal E",
    [15755] = "star seal F",
    [15756] = "line seal A",
    [15757] = "line seal B",
    [15758] = "line seal C",
    [15759] = "line seal D",
    [15760] = "smoke seal A",
    [15761] = "smoke seal B",
    [15762] = "smoke seal C",
    [15763] = "smoke seal D",
    [15764] = "ele seal A",
    [15765] = "ele seal B",
    [15766] = "ele seal C",
    [15767] = "ele seal D",
    [15768] = "foamy seal A",
    [15769] = "foamy seal B",
    [15770] = "foamy seal C",
    [15771] = "foamy seal D",
    [15772] = "fire seal A",
    [15773] = "fire seal B",
    [15774] = "fire seal C",
    [15775] = "fire seal D",
    [15776] = "party seal A",
    [15777] = "party seal B",
    [15778] = "party seal C",
    [15779] = "party seal D",
    [15780] = "flora seal A",
    [15781] = "flora seal B",
    [15782] = "flora seal C",
    [15783] = "flora seal D",
    [15784] = "flora seal E",
    [15785] = "flora seal F",
    [15786] = "song seal A",
    [15787] = "song seal B",
    [15788] = "song seal C",
    [15789] = "song seal D",
    [15790] = "song seal E",
    [15791] = "song seal F",
    [15792] = "song seal G",
    [15793] = "burst seal",
    [15794] = "liquid seal",
    [15795] = "twinkle seal",
    [16382] = "acorn",
    [16383] = "antlers",
    [16384] = "artist canvas",
    [16385] = "artist brush with ink",
    [16386] = "artist brush",
    [16387] = "artist palette",
    [16388] = "bag of candies",
    [16389] = "bamboo stick",
    [16390] = "banana sash",
    [16391] = "banana skin",
    [16392] = "battle stone",
    [16393] = "blazing bone",
    [16394] = "bony tail",
    [16395] = "clay lump",
    [16396] = "coal",
    [16397] = "crystaline spikes",
    [16398] = "cure herb",
    [16399] = "dark claws",
    [16400] = "dark crystal",
    [16401] = "decorative ribbon",
    [16402] = "iron loadstone",
    [16403] = "luminous orb",
    [16404] = "poisonous slime",
    [16405] = "pot of flames",
    [16406] = "spider fangs",
    [16407] = "spider silk",
    [16408] = "spiderwebs",
    [16409] = "wool",
    [16417] = "ivysaur doll",
    [16418] = "venusaur doll",
    [16419] = "charmander doll",
    [16420] = "charmeleon doll",
    [16421] = "charizard doll",
    [16422] = "squirtle doll",
    [16423] = "wartortle doll",
    [16424] = "blastoise doll",
    [16425] = "caterpie doll",
    [16426] = "metapod doll",
    [16427] = "butterfree doll",
    [16428] = "weedle doll",
    [16429] = "kakuna doll",
    [16430] = "beedrill doll",
    [16431] = "pidgey doll",
    [16432] = "pidgeotto doll",
    [16433] = "rattata doll",
    [16434] = "raticate doll",
    [16435] = "spearow doll",
    [16436] = "fearow doll",
    [16437] = "ekans doll",
    [16438] = "arbok doll",
    [16439] = "sandshrew doll",
    [16440] = "sandslash doll",
    [16441] = "nidorana doll",
    [16442] = "nidorina doll",
    [16443] = "nidoqueen doll",
    [16444] = "nidorano doll",
    [16445] = "nidorino doll",
    [16446] = "nidoking doll",
    [16447] = "clefairy doll",
    [16448] = "clefable doll",
    [16449] = "vulpix doll",
    [16450] = "ninetales doll",
    [16451] = "wigglytuff doll",
    [16452] = "zubat doll",
    [16453] = "golbat doll",
    [16454] = "oddish doll",
    [16455] = "gloom doll",
    [16456] = "vileplume doll",
    [16457] = "paras doll",
    [16458] = "parasect doll",
    [16459] = "venonat doll",
    [16460] = "venomoth doll",
    [16461] = "diglett doll",
    [16462] = "dugtrio doll",
    [16463] = "meowth doll",
    [16464] = "persian doll",
    [16465] = "golduck doll",
    [16466] = "mankey doll",
    [16467] = "primeape doll",
    [16468] = "growlithe doll",
    [16469] = "arcanine doll",
    [16470] = "poliwag doll",
    [16471] = "poliwhirl doll",
    [16472] = "abra doll",
    [16473] = "kadabra doll",
    [16474] = "alakazam doll",
    [16475] = "machop doll",
    [16476] = "machoke doll",
    [16477] = "machamp doll",
    [16478] = "bellsprout doll",
    [16479] = "weepinbell doll",
    [16480] = "victreebel doll",
    [16481] = "tentacool doll",
    [16482] = "tentacruel doll",
    [16483] = "geodude doll",
    [16484] = "graveler doll",
    [16485] = "golem doll",
    [16486] = "ponyta doll",
    [16487] = "rapidash doll",
    [16488] = "slowpoke doll",
    [16489] = "magnemite doll",
    [16490] = "magneton doll",
    [16491] = "farfetchd doll",
    [16492] = "doduo doll",
    [16493] = "dodrio doll",
    [16494] = "dewgong doll",
    [16495] = "grimer doll",
    [16496] = "muk doll",
    [16497] = "shellder doll",
    [16498] = "cloyster doll",
    [16499] = "gastly doll",
    [16500] = "haunter doll",
    [16501] = "gengar doll",
    [16502] = "onix doll",
    [16503] = "drowzee doll",
    [16504] = "hypno doll",
    [16505] = "krabby doll",
    [16506] = "kingler doll",
    [16507] = "voltorb doll",
    [16508] = "electrode doll",
    [16509] = "exeggcute doll",
    [16510] = "exeggutor doll",
    [16511] = "marowak doll",
    [16512] = "hitmonlee doll",
    [16513] = "hitmonchan doll",
    [16514] = "lickitung doll",
    [16515] = "koffing doll",
    [16516] = "weezing doll",
    [16517] = "rhyhorn doll",
    [16518] = "rhydon doll",
    [16519] = "tangela doll",
    [16520] = "kangaskhan doll",
    [16521] = "horsea doll",
    [16522] = "seadra doll",
    [16523] = "goldeen doll",
    [16524] = "seaking doll",
    [16525] = "staryu doll",
    [16526] = "starmie doll",
    [16527] = "mr. mime doll",
    [16528] = "scyther doll",
    [16529] = "jynx doll",
    [16530] = "electabuzz doll",
    [16531] = "magmar doll",
    [16532] = "pinsir doll",
    [16533] = "tauros doll",
    [16534] = "magikarp doll",
    [16535] = "gyarados doll",
    [16536] = "ditto doll",
    [16537] = "eevee doll",
    [16538] = "vaporeon doll",
    [16539] = "jolteon doll",
    [16540] = "flareon doll",
    [16541] = "porygon doll",
    [16542] = "omastar doll",
    [16543] = "kabutops doll",
    [16544] = "aerodactyl doll",
    [16545] = "snorlax doll",
    [16546] = "dratini doll",
    [16547] = "dragonair doll",
    [16548] = "dragonite doll",
    [16549] = "chikorita doll",
    [16550] = "bayleef doll",
    [16551] = "meganium doll",
    [16552] = "cyndaquil doll",
    [16553] = "quilava doll",
    [16554] = "typhlosion doll",
    [16555] = "totodile doll",
    [16556] = "croconaw doll",
    [16557] = "feraligatr doll",
    [16558] = "sentret doll",
    [16559] = "furret doll",
    [16560] = "hoothoot doll",
    [16561] = "noctowl doll",
    [16562] = "ledyba doll",
    [16563] = "ledian doll",
    [16564] = "spinarak doll",
    [16565] = "ariados doll",
    [16566] = "crobat doll",
    [16567] = "chinchou doll",
    [16568] = "lanturn doll",
    [16569] = "pichu doll",
    [16570] = "cleffa doll",
    [16571] = "igglybuff doll",
    [16572] = "togepi doll",
    [16573] = "togetic doll",
    [16574] = "natu doll",
    [16575] = "xatu doll",
    [16576] = "mareep doll",
    [16577] = "flaaffy doll",
    [16578] = "ampharos doll",
    [16579] = "bellossom doll",
    [16580] = "marill doll",
    [16581] = "azumarill doll",
    [16582] = "sudowoodo doll",
    [16583] = "politoed doll",
    [16584] = "hoppip doll",
    [16585] = "skiploom doll",
    [16586] = "jumpluff doll",
    [16587] = "aipom doll",
    [16588] = "sunkern doll",
    [16589] = "sunflora doll",
    [16590] = "yanma doll",
    [16591] = "wooper doll",
    [16592] = "quagsire doll",
    [16593] = "espeon doll",
    [16594] = "umbreon doll",
    [16595] = "murkrow doll",
    [16596] = "slowking doll",
    [16597] = "misdreavus doll",
    [16598] = "wobbuffet doll",
    [16599] = "girafarig doll",
    [16600] = "pineco doll",
    [16601] = "forretress doll",
    [16602] = "dunsparce doll",
    [16603] = "gligar doll",
    [16604] = "steelix doll",
    [16605] = "snubbull doll",
    [16606] = "granbull doll",
    [16607] = "qwilfish doll",
    [16608] = "scizor doll",
    [16609] = "shuckle doll",
    [16610] = "heracross doll",
    [16611] = "sneasel doll",
    [16612] = "teddiursa doll",
    [16613] = "ursaring doll",
    [16614] = "slugma doll",
    [16615] = "magcargo doll",
    [16616] = "swinub doll",
    [16617] = "piloswine doll",
    [16618] = "corsola doll",
    [16619] = "remoraid doll",
    [16620] = "octillery doll",
    [16621] = "delibird doll",
    [16622] = "mantine doll",
    [16623] = "skarmory doll",
    [16624] = "houndour doll",
    [16625] = "houndoom doll",
    [16626] = "kingdra doll",
    [16627] = "phanpy doll",
    [16628] = "donphan doll",
    [16629] = "porygon2 doll",
    [16630] = "stantler doll",
    [16631] = "smeargle doll",
    [16632] = "tyrogue doll",
    [16633] = "hitmontop doll",
    [16634] = "smoochum doll",
    [16635] = "elekid doll",
    [16636] = "magby doll",
    [16637] = "miltank doll",
    [16638] = "blissey doll",
    [16639] = "raikou doll",
    [16640] = "entei doll",
    [16641] = "suicune doll",
    [16642] = "larvitar doll",
    [16643] = "pupitar doll",
    [16644] = "tyranitar doll",
    [16645] = "ho-oh doll",
    [16646] = "celebi doll",
    [16647] = "cubone lamp",
    [16648] = "cubone lamp",
    [16649] = "chinchou lamp",
    [16650] = "chinchou lamp",
    [16651] = "pikachu lamp",
    [16652] = "pikachu lamp",
    [16653] = "gastly lamp",
    [16654] = "gastly lamp",
    [16655] = "cubone lamp",
    [16656] = "cubone lamp",
    [16658] = "pichu carpet",
    [16659] = "aipom carpet",
    [16660] = "noctowl carpet",
    [16661] = "mastery curtain",
    [16662] = "mastery curtain",
    [16663] = "mastery curtain",
    [16664] = "mastery curtain",
    [16665] = "mastery curtain",
    [16666] = "mastery curtain",
    [16667] = "mastery curtain",
    [16668] = "mastery curtain",
    [16669] = "mastery curtain",
    [16686] = "Sky Plate",
    [16687] = "Spooky Plate",
    [16688] = "Fire Stone",
    [16689] = "Moon Stone",
    [16690] = "Sun Stone",
    [16691] = "Leaf Stone",
    [16692] = "Thunderstone",
    [16693] = "Water Stone",
    [16694] = "Up-Grade",
    [16695] = "Dragon Scale",
    [16696] = "King's Rock",
    [16697] = "Metal Coat",
    [16698] = "Soothe Bell",
    [16699] = "Punch Machine",
    [16700] = "Kick Machine",
    [16701] = "Spin Machine",
    [16754] = "Blastertoise artifacts",
    [16755] = "Great Saul artifacts",
    [16756] = "Pink Fury artifacts",
    [16757] = "Kirby artifacts",
    [16758] = "Cesar, The Simian artifacts",
    [16759] = "Winged Wisdom artifacts",
    [16760] = "Phyllo Terribil artifacts",
    [16761] = "Grisly Mind artifacts",
    [16762] = "DoomBoy artifacts",
    [16763] = "Toby artifacts",
    [16764] = "The A. Mesmer artifacts",
    [16765] = "Mad Mum artifacts",
    [16766] = "Charles Spencer artifacts",
    [16767] = "Twisted Blades artifacts",
    [16768] = "Sweet Lover artifacts",
    [16769] = "The Turbo artifacts",
    [16770] = "Flesh'n Fire artifacts",
    [16771] = "King Panlong artifacts",
    [16772] = "Mr. Gormandize artifacts",
    [16773] = "Smaug artifacts",
    [17284] = "berry seed box",
    [17285] = "seal box #1",
    [17286] = "seal box #2",
    [17287] = "seal box #3",
    [17368] = "gengar backpack",
    [17381] = "black ball paint ticket",
    [17382] = "fang ball paint ticket",
    [17383] = "horn ball paint ticket",
    [17395] = "christmas #1 clothes kit",
    [17396] = "christmas #2 clothes kit",
    [17397] = "christmas #3 clothes kit",
    [17401] = "furniture package",
    [17516] = "blue egg paint ticket",
    [17517] = "carrot paint ticket",
    [17518] = "chocolate paint ticket",
    [17519] = "green egg paint ticket",
    [17520] = "white egg paint ticket",
    [17544] = "dragonborn paint ticket",
    [17545] = "grinch paint ticket",
    [17546] = "minus paint ticket",
    [17557] = "fire paint ticket",
    [17558] = "thunder paint ticket",
    [17559] = "water paint ticket",
    [17560] = "researcher clothes kit",
    [17561] = "TM 48",
    [17562] = "TM 49",
    [17563] = "TM 50",
    [17564] = "TM 51",
    [17565] = "TM 52",
    [17566] = "TM 53",
    [17567] = "TM 54",
    [17568] = "TM 55",
    [17569] = "TM 56",
    [17570] = "TM 57",
    [17571] = "TM 58",
    [17572] = "TM 59",
    [17573] = "TM 60",
    [17574] = "TM 61",
    [17575] = "TM 62",
    [17576] = "TM 63",
    [17577] = "TM 64",
    [17578] = "TM 65",
    [17579] = "TM 66",
    [17580] = "TM 67",
    [17590] = "caterpie backpack",
    [17600] = "nightmare paint ticket",
    [17601] = "shadow paint ticket",
    [17602] = "spark paint ticket",
    [17603] = "doll box",
    [17667] = "bug type locker",
    [17668] = "dark type locker",
    [17669] = "dragon type locker",
    [17670] = "electric type locker",
    [17671] = "fairy type locker",
    [17672] = "fighting type locker",
    [17673] = "fire type locker",
    [17674] = "flying type locker",
    [17675] = "ghost type locker",
    [17676] = "grass type locker",
    [17677] = "ground type locker",
    [17678] = "ice type locker",
    [17679] = "normal type locker",
    [17680] = "poison type locker",
    [17681] = "psychic type locker",
    [17682] = "rock type locker",
    [17683] = "steel type locker",
    [17684] = "water type locker",
    [17721] = "",
    [17721] = "avalanche paint ticket",
    [17722] = "blaze paint ticket",
    [17723] = "gaia paint ticket",
    [17724] = "heremit paint ticket",
    [17725] = "hurricane paint ticket",
    [17726] = "spectrum paint ticket",
    [17727] = "vital paint ticket",
    [17728] = "voltagic paint ticket",
    [17729] = "zen paint ticket",
    [17729] = "",
    [17739] = "bat ticket",
    [17740] = "dark eye ticket",
    [17741] = "spectral ticket",
    [17742] = "black wizard pikachu doll",
    [17743] = "blue wizard pikachu doll",
    [17744] = "vampire bulbasaur doll",
    [17745] = "wizard charmander doll",
    [17746] = "pumpkinhead squirtle doll",
    [17747] = "halloween #5 clothes kit",
    [17909] = "",
    [17910] = "",
    [17911] = "",
    [17912] = "",
    [18416] = "avalanche doll",
    [18417] = "gaia doll",
    [18418] = "vital doll",
    [18419] = "blaze doll",
    [18420] = "voltagic doll",
    [18421] = "hurricane doll",
    [18422] = "spectrum doll",
    [18423] = "zen doll",
    [18424] = "heremit doll",
    [18484] = "",
    [22107] = "calcium vitamin",
    [22108] = "carbos vitamin",
    [22109] = "hp up vitamin",
    [22110] = "iron vitamin",
    [22111] = "pp max vitamin",
    [22112] = "pp up vitamin",
    [22113] = "protein vitamin",
    [22114] = "zinc vitamin",
    [22121] = "jynx bag",
    [22122] = "golduck bag",
    [22123] = "aerodactyl bag",
    [22124] = "eevee bag",
    [22125] = "sneasel bag",
    [22126] = "mr. mime bag",
    [22127] = "flareon bag",
    [22128] = "jolteon bag",
    [22129] = "vaporeon bag",
    [22130] = "wartortle bag",
    [22131] = "sandslash bag",
    [22132] = "umbreon bag",
    [22133] = "espeon bag",
    [22134] = "scizor bag",
    [22135] = "chikorita bag",
    [22136] = "mew bag",
    [22137] = "mewtwo bag",
    [22138] = "arbok bag",
    [22139] = "charizard bag",
    [22140] = "pikachu bag",
    [22141] = "snorlax bag",
    [22142] = "scyther bag",
    [22143] = "victreebel bag",
    [22144] = "pidgeot bag",
    [22145] = "machamp bag",
    [22146] = "haunter bag",
    [22147] = "marowak bag",
    [22148] = "dragonite bag",
    [22149] = "red bag",
    [22150] = "white bag",
    [22151] = "yellow bag",
    [22152] = "green bag",
    [22153] = "blue bag",
    [22155] = "burning charcoal",
    [22156] = "metal bar",
    [22157] = "poison flask",
    [22158] = "pot of seed",
    [22159] = "water crystal",
    [22160] = "hurricane backpack",
    [22161] = "zen backpack",
    [22162] = "vital backpack",
    [22163] = "gaia backpack",
    [22164] = "heremit backpack",
    [22165] = "voltagic backpack",
    [22166] = "blaze backpack",
    [22167] = "avalanche backpack",
    [22168] = "spectrum backpack",
    [22170] = "held black belt",
    [22171] = "held black glasses",
    [22172] = "held charcoal",
    [22173] = "held dragon fang",
    [22174] = "held hard stone",
    [22175] = "held magnet",
    [22176] = "held metal coat",
    [22177] = "held miracle seed",
    [22178] = "held mystic water",
    [22179] = "held never melt ice",
    [22180] = "held pink bow",
    [22181] = "held poison barb",
    [22182] = "held polkadot bow",
    [22183] = "held sharp beak",
    [22184] = "held silk scarf",
    [22185] = "held silver powder",
    [22186] = "held soft sand",
    [22187] = "held spell tag",
    [22188] = "held twisted spoon",
    [22603] = "Pixie Plate",
}

function getItemNameByClientId(id)
    return ITEM_NAME_BY_ID[tonumber(id)] and ITEM_NAME_BY_ID[tonumber(id)] or ""
end

--[[
function onSay(cid, words, param, channel)
	local out = ""

	for x = 100, 66000 do
		local info = getItemInfo(x)
		if (info and info.wareId > 0) then
			out = out .. string.concat("[", getItemClientId(x), "] = \"", getItemNameById(x), "\",\n")
		end
	end

	local file = io.open("wareNames.txt", "w+")
	file:write(out)
	file:close()
	return true
end
 ]]