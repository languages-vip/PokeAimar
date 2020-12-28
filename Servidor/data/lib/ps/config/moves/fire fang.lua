MOVES["Fire Fang"] = {
    description = "Fire Fang deals damage and has a 10% chance of burning the target, plus a 10% chance of causing the target to flinch.",
    makeContact = true,
    category = MOVE_CATEGORY.PHYSICAL,
    clientIconId = 12046,
    iconId = 0,
    dType = DAMAGE_TYPE_FIRE,
    functionName = "FireFang",
    type = SKILLS_TYPES.TARGET,
    requiredEnergy = 65,
    requiredLevel = 20,
    damage = 65,
    damageType = ELEMENT_FIRE,
    effect = EFFECT_BIG_BITE,
    projectile = nil,
    maxDistance = 1,
    cooldownTime = 10,
    cooldownStorage = 15144
}