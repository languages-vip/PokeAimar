MOVES["Jump Kick"] = {
    description = "Jump Kick deals damage and has no secondary effect.",
    makeContact = true,
    makeRecoil = true,
    category = MOVE_CATEGORY.PHYSICAL,
    clientIconId = 11730,
    iconId = 13356,
    dType = DAMAGE_TYPE_FIGHTING,
    functionName = "JumpKick",
    type = SKILLS_TYPES.TARGET,
    requiredEnergy = 100,
    requiredLevel = 30,
    damage = 100,
    damageType = ELEMENT_FIGHT,
    effect = EFFECT_KICK_TWO,
    projectile = PROJECTILE_GRAVEL,
    maxDistance = 1,
    cooldownTime = 11,
    cooldownStorage = 15038
}