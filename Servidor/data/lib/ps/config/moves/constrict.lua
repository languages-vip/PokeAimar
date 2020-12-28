MOVES["Constrict"] = {
    description = "Constrict deals damage and has a 10% chance of lowering the target's Speed by one stage.",
    makeContact = true,
    category = MOVE_CATEGORY.PHYSICAL,
    clientIconId = 12103,
    iconId = 0,
    dType = DAMAGE_TYPE_NORMAL,
    functionName = "Constrict",
    type = SKILLS_TYPES.AREA,
    requiredEnergy = 50,
    requiredLevel = 15,
    damage = 10,
    damageType = ELEMENT_NORMAL,
    effect = EFFECT_BLOW,
    areaEffect = EFFECT_ROOT_EMERGE,
    areaName = "bigArea",
    area = bigArea,
    cooldownTime = 15,
    cooldownStorage = 15201
}