import { z } from 'zod'
import { buttonItemSchema } from '../blocks/inputs/choice'
import { conditionItemSchema } from '../blocks/logic/condition'
import { optionsItemSchema } from '../blocks/inputs/options'

const itemSchema = buttonItemSchema.or(conditionItemSchema).or(optionsItemSchema)

export type Item = z.infer<typeof itemSchema>
