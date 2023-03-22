import { z } from 'zod'
import { optionBaseSchema, blockBaseSchema } from '../baseSchemas'
import { defaultButtonLabel } from './constants'
import { InputBlockType } from './enums'
import { textInputOptionsBaseSchema } from './text'

export const pancardOptionsSchema = optionBaseSchema
  .merge(textInputOptionsBaseSchema)
  .merge(
    z.object({
      retryMessageContent: z.string(),
    })
  )

export const pancardSchema = blockBaseSchema.merge(
  z.object({
    type: z.enum([InputBlockType.PANCARD]),
    options: pancardOptionsSchema,
  })
)

export const defaultPancardOptions: PancardOptions = {
  labels: {
    button: defaultButtonLabel,
    placeholder: 'Type your PAN number...',
  },
  retryMessageContent:
    "This PAN number doesn't seem to be valid. Can you type it again?",
}

export type PancardBlock = z.infer<typeof pancardSchema>
export type PancardOptions = z.infer<typeof pancardOptionsSchema>
