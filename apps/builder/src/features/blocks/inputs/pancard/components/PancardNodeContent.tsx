import React from 'react'
import { Text } from '@chakra-ui/react'
import { PancardBlock } from '@typebot.io/schemas'
import { WithVariableContent } from '@/features/graph/components/nodes/block/WithVariableContent'

type Props = {
  variableId?: string
  placeholder: PancardBlock['options']['labels']['placeholder']
}

export const PancardNodeContent = ({ variableId, placeholder }: Props) =>
  variableId ? (
    <WithVariableContent variableId={variableId} />
  ) : (
    <Text color={'gray.500'}>{placeholder}</Text>
  )
