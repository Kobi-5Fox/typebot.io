import { z } from 'zod'
import { ItemType } from '../../items/enums'
import { itemBaseSchema } from '../../items/baseSchemas'
import { optionBaseSchema, blockBaseSchema } from '../baseSchemas'
import { defaultOptionsLabel } from './constants'
import { InputBlockType } from './enums'

export const optionsInputOptionsSchema = optionBaseSchema.and(
  z.object({
    isMultipleChoice: z.boolean(),
    optionsLabel: z.string(),
    dynamicVariableId: z.string().optional(),
  })
)

export const defaultOptionsInputOptions: OptionsInputOptions = {
  optionsLabel: defaultOptionsLabel,
  isMultipleChoice: false,
}

export const optionsItemSchema = itemBaseSchema.and(
  z.object({
    type: z.literal(ItemType.OPTION),
    content: z.string().optional(),
  })
)

export const optionsInputSchema = blockBaseSchema.and(
  z.object({
    type: z.enum([InputBlockType.OPTION]),
    items: z.array(optionsItemSchema),
    options: optionsInputOptionsSchema,
  })
)

export type OptionsItem = z.infer<typeof optionsItemSchema>
export type OptionsInputBlock = z.infer<typeof optionsInputSchema>
export type OptionsInputOptions = z.infer<typeof optionsInputOptionsSchema>
