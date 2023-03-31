import { SendButton } from '@/components/SendButton'
import { InputSubmitContent } from '@/types'
import type { ChoiceInputBlock } from '@typebot.io/schemas'
import { createSignal, For } from 'solid-js'

type Props = {
  inputIndex: number
  block: ChoiceInputBlock
  onSubmit: (value: InputSubmitContent) => void
}

export const ChoiceForm = (props: Props) => {
  const [selectedIndices, setSelectedIndices] = createSignal<number[]>([])

  // const [dropdownVisible, setDropdownVisible] = createSignal<boolean>(false)

  const handleSelect = (itemIndex: number) => {
    console.log('Index ', itemIndex)
    if (itemIndex > 0) {
      if (props.block.options?.isMultipleChoice)
        toggleSelectedItemIndex(itemIndex - 1)
      else
        props.onSubmit({
          value: props.block.items[itemIndex - 1].content ?? '',
        })
      console.log('Indices ', selectedIndices())
    }
  }
  const handleClick = (itemIndex: number) => {
    if (props.block.options?.isMultipleChoice)
      toggleSelectedItemIndex(itemIndex)
    else
      props.onSubmit({ value: props.block.items[itemIndex].content ?? '' })
    console.log('Indices ', selectedIndices())
  }

  const toggleSelectedItemIndex = (itemIndex: number) => {
    const existingIndex = selectedIndices().indexOf(itemIndex)
    if (existingIndex !== -1) {
      setSelectedIndices((selectedIndices) =>
        selectedIndices.filter((index: number) => index !== itemIndex)
      )
    } else {
      setSelectedIndices((selectedIndices) => [...selectedIndices, itemIndex])
    }
  }

  const handleSubmit = () =>
    props.onSubmit({
      value: selectedIndices()
        .map((itemIndex: number) => props.block.items[itemIndex].content)
        .join(', '),
    })

  return (
    <form class="flex flex-col items-end " onSubmit={handleSubmit}>
      {props.block.options.isDropdownInput ? (
        <div class="flex flex-wrap justify-end">
          <span class="group flex border-purple-600 flex-col rounded">
            <select
              multiple={props.block.options.isMultipleChoice}
              title={'Option Select'}
              onClick={(e: { currentTarget: { selectedIndex: number } }) => {
                handleSelect(e.currentTarget.selectedIndex)
              }}
            >
              <option class="bg-white text-gray-400">Select...</option>
              <For
                each={props.block.items}
                fallback={<div>No Items to Choose!</div>}
              >
                {(item, index) => (
                  <option
                    class={
                      selectedIndices().indexOf(index()) !== -1
                        ? 'bg-white text-purple-600'
                        : 'bg-purple-600 text-white'
                    }
                    value={item.id}
                  >
                    {item.content}
                  </option>
                )}
              </For>
            </select>
            {props.inputIndex === 0 && props.block.items.length === 1 && (
              <span class="flex h-3 w-3 absolute top-0 right-0 -mt-1 -mr-1 ping">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full brightness-225 opacity-75" />
                <span class="relative inline-flex rounded-full h-3 w-3 brightness-200" />
              </span>
            )}
          </span>
        </div>
      ) : (
        <div class="flex flex-wrap justify-end">
          <For each={props.block.items} 
                fallback={<div>No Items to Choose!</div>}
                >
            {(item,index) => (
              <span class="relative inline-flex ml-2 mb-2">
                <button
                  role={
                    props.block.options?.isMultipleChoice
                      ? 'checkbox'
                      : 'button'
                  }
                  type="button"
                  on:click={() => handleClick(index())}
                  class={
                    'py-2 px-4 text-left font-semibold rounded-md transition-all filter hover:brightness-90 active:brightness-75 duration-100 focus:outline-none typebot-button ' +
                    (selectedIndices().some(
                      (selectedIndex: unknown) => selectedIndex === index()
                    ) || !props.block.options?.isMultipleChoice
                      ? ''
                      : 'selectable')
                  }
                  data-itemid={item.id}
                >
                  {item.content}
                </button>
                {props.inputIndex === 0 && props.block.items.length === 1 && (
                  <span class="flex h-3 w-3 absolute top-0 right-0 -mt-1 -mr-1 ping">
                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full brightness-225 opacity-75" />
                    <span class="relative inline-flex rounded-full h-3 w-3 brightness-200" />
                  </span>
                )}
              </span>
            )}
          </For>
        </div>
      )}

      <div class="flex">
        {selectedIndices().length > 0 && (
          <SendButton disableIcon>
            {props.block.options?.buttonLabel ?? 'Send'}
          </SendButton>
        )}
      </div>
    </form>
  )
}
