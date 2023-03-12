import { TextInput } from '@/components/inputs'
import { SwitchWithLabel } from '@/components/inputs/SwitchWithLabel'
import { VariableSearchInput } from '@/components/inputs/VariableSearchInput'
import { MoreInfoTooltip } from '@/components/MoreInfoTooltip'
import { FormControl, FormLabel, Stack } from '@chakra-ui/react'
import { OptionsInputOptions, Variable } from 'models'

type Props = {
  options?: OptionsInputOptions
  onOptionsChange: (options: OptionsInputOptions) => void
}

export const OptionsBlockSettings = ({ options, onOptionsChange }: Props) => {
  const handleIsMultipleChange = (isMultipleChoice: boolean) =>
    options && onOptionsChange({ ...options, isMultipleChoice })
  const handleOptionsLabelChange = (optionsLabel: string) =>
    options && onOptionsChange({ ...options, optionsLabel })
  const handleVariableChange = (variable?: Variable) =>
    options && onOptionsChange({ ...options, variableId: variable?.id })
  const handleDynamicVariableChange = (variable?: Variable) =>
    options && onOptionsChange({ ...options, dynamicVariableId: variable?.id })

  return (
    <Stack spacing={4}>
      <SwitchWithLabel
        label="Multiple choice?"
        initialValue={options?.isMultipleChoice ?? false}
        onCheckChange={handleIsMultipleChange}
      />
      {options?.isMultipleChoice && (
        <TextInput
          label="Options label:"
          defaultValue={options?.optionsLabel ?? 'Opt'}
          onChange={handleOptionsLabelChange}
        />
      )}
      <FormControl>
        <FormLabel>
          Dynamic items from variable:{' '}
          <MoreInfoTooltip>
            If defined, optionss will be dynamically displayed based on what the
            variable contains.
          </MoreInfoTooltip>
        </FormLabel>
        <VariableSearchInput
          initialVariableId={options?.dynamicVariableId}
          onSelectVariable={handleDynamicVariableChange}
        />
      </FormControl>
      <Stack>
        <FormLabel mb="0" htmlFor="variable">
          Save answer in a variable:
        </FormLabel>
        <VariableSearchInput
          initialVariableId={options?.variableId}
          onSelectVariable={handleVariableChange}
        />
      </Stack>
    </Stack>
  )
}
