import { PlusIcon } from '@/components/icons'
import { useTypebot } from '@/features/editor'
import {
  Editable, EditableInput, EditablePreview, Fade, Flex, IconButton
} from '@chakra-ui/react'
import { ItemIndices, ItemType, OptionsItem } from 'models'
import React, { useRef, useState } from 'react'
import { isNotDefined } from 'utils'
  
  type Props = {
    item: OptionsItem
    indices: ItemIndices
    isMouseOver: boolean
  }
  export const OptionsItemNode = ({ item, indices, isMouseOver }: Props) => {
    const { deleteItem, updateItem, createItem } = useTypebot()
    const [itemValue, setItemValue] = useState(item.content ?? 'Click to edit')
    const editableRef = useRef<HTMLDivElement | null>(null)
  
    const handleInputSubmit = () => {
      if (itemValue === '') deleteItem(indices)
      else{
        updateItem(indices, { content: itemValue === '' ? undefined : itemValue })
    }
    }
    const handleKeyPress = (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === 'Escape' && itemValue === 'Click to edit') deleteItem(indices)
      if (e.key === 'Enter' && itemValue !== '' && itemValue !== 'Click to edit')
        handlePlusClick()
    }
  
    const handlePlusClick = () => {
      const itemIndex = indices.itemIndex + 1
      createItem(
        { blockId: item.blockId, type: ItemType.OPTION },
        { ...indices, itemIndex }
      )
    }
  
    return (
      <Flex px={4} py={2} justify="center" w="90%" pos="relative">
        <Editable
          ref={editableRef}
          flex="1"
          startWithEditView={isNotDefined(item.content)}
          value={itemValue}
          onChange={setItemValue}
          onSubmit={handleInputSubmit}
          onKeyDownCapture={handleKeyPress}
          maxW="180px"
        >
          <EditablePreview
            w="full"
            color={item.content !== 'Click to edit' ? 'inherit' : 'gray.500'}
            cursor="pointer"
          />
          <EditableInput />
        </Editable>
        <Fade
          in={isMouseOver}
          style={{
            position: 'absolute',
            bottom: '-15px',
            zIndex: 3,
            left: '90px',
          }}
          unmountOnExit
        >
          <IconButton
            aria-label="Add option"
            icon={<PlusIcon />}
            size="xs"
            shadow="md"
            colorScheme="gray"
            onClick={handlePlusClick}
          />
        </Fade>
      </Flex>
    )
  }
  